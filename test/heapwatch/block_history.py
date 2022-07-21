#!/usr/bin/env python3
#
# pip install py-algorand-sdk

import argparse
import base64
import logging
import os
import re
import signal
import sys
import time

import algosdk
from algosdk.encoding import msgpack
from algosdk.v2client.algod import AlgodClient

logger = logging.getLogger(__name__)

def addr_token_from_algod(algorand_data):
    with open(os.path.join(algorand_data, 'algod.net')) as fin:
        addr = fin.read().strip()
    with open(os.path.join(algorand_data, 'algod.token')) as fin:
        token = fin.read().strip()
    if not addr.startswith('http'):
        addr = 'http://' + addr
    return addr, token

def loads(blob):
    return msgpack.loads(base64.b64decode(blob), strict_map_key=False)

def dumps(blob):
    return base64.b64encode(msgpack.dumps(blob))

class Fetcher:
    def __init__(self, algorand_data=None, token=None, addr=None, headers=None, prev_round=None, outpath=None):
        """
        algorand_data = path to algod data dir
        addr, token = algod URI and access token
        headers = dict of HTTP headers to send to algod
        prev_round = start with (prev_round + 1)
        outpath = path to append base64-msgpack-per-line data to
        """
        self.algorand_data = algorand_data
        self.token = token
        self.addr = addr
        self.headers = headers
        self._algod = None
        self.go = True
        self.prev_round = prev_round
        self.block_time = None
        self.outpath = outpath
        self._outf = None
        if outpath and prev_round is None:
            # load data, find last known round in data
            try:
                with open(outpath) as fin:
                    for line in fin:
                        if not line:
                            continue
                        line = line.strip()
                        if not line:
                            continue
                        if line[0] == '#':
                            continue
                        ob = loads(line)
                        rnd = ob['block'].get('rnd', 0)
                        if (self.prev_round is None) or (rnd > self.prev_round):
                            self.prev_round = rnd
            except:
                pass # whatever
        return

    def algod(self):
        "return an open algosdk.v2client.algod.AlgodClient"
        if self._algod is None:
            if self.algorand_data:
                addr, token = addr_token_from_algod(self.algorand_data)
                logger.debug('algod from %r, (%s %s)', self.algorand_data, addr, token)
            else:
                token = self.token
                addr = self.addr
                logger.debug('algod from args (%s %s)', self.addr, self.token)
            self._algod = AlgodClient(token, addr, headers=self.headers)
        return self._algod

    def outf(self):
        if self._outf is None:
            self._outf = open(self.outpath, 'ab')
        return self._outf

    def nextblock(self, lastround=None, retries=30):
        trycount = 0
        while (trycount < retries) and self.go:
            trycount += 1
            try:
                return self._nextblock_inner(lastround)
            except Exception as e:
                if trycount >= retries:
                    logger.error('too many errors in nextblock retries')
                    raise
                else:
                    logger.warning('error in nextblock(%r) (retrying): %s', lastround, e)
                    self._algod = None # retry with a new connection
                    time.sleep(1.2)
        return None

    def _nextblock_inner(self, lastround):
        self.block_time = None
        algod = self.algod()
        if lastround is None:
            status = algod.status()
            lastround = status['last-round']
            logger.debug('nextblock status last-round %s', lastround)
        else:
            try:
                blk = self.algod().block_info(lastround + 1, response_format='msgpack')
                if blk:
                    return blk
                logger.warning('null block %d, lastround=%r', lastround+1, lastround)
            except Exception as e:
                pass
                #logger.debug('could not get block %d: %s', lastround + 1, e, exc_info=True)
        status = algod.status_after_block(lastround)
        block_time = time.time() # the block has happened, don't count block data transit time
        nbr = status['last-round']
        retries = 30
        while (nbr > lastround + 1) and self.go:
            # if more than one block elapsed, we don't have a good time for either block
            block_time = None
            # try lastround+1 one last time
            try:
                blk = self.algod().block_info(lastround + 1, response_format='msgpack')
                if blk:
                    return blk
                logger.warning('null block %d, lastround=%r, status.last-round=%d', lastround+1, lastround, nbr)
                time.sleep(1.1)
                retries -= 1
                if retries <= 0:
                    raise Exception("too many null block for %d", lastround+1)
            except:
                break
        blk = self.algod().block_info(nbr, response_format='msgpack')
        if blk:
            self.block_time = block_time
            return blk
        raise Exception('got None for blk {}'.format(nbr))

    def loop(self):
        """Start processing blocks and txns
        runs until error or bot.go=False
        """
        if self.prev_round is not None:
            lastround = self.prev_round
        else:
            lastround = -1
        try:
            self._loop_inner(lastround)
        finally:
            self.close()

    def _loop_inner(self, lastround):
        while self.go:
            b = self.nextblock(lastround)
            if b is None:
                print("got None nextblock. exiting")
                return
            b = msgpack.loads(b, strict_map_key=False)
            nowround = b['block'].get('rnd', 0)
            if (lastround is not None) and (nowround != lastround + 1):
                logger.info('round jump %d to %d', lastround, nowround)
            self._block_handler(b)
            lastround = nowround

    def _block_handler(self, b):
        # throw away txns, count is kept in round differential ['block']['tc']
        b['block'].pop('txns', [])
        # throw away certs
        b.pop('cert', None)
        # Add fine grained time. This should be better than ['block']['ts']
        b['_time'] = self.block_time or time.time()
        self.outf().write(dumps(b) + b'\n')

    def close(self):
        self._algod = None

def header_list_to_dict(hlist):
    if not hlist:
        return None
    p = re.compile(r':\s+')
    out = {}
    for x in hlist:
        a, b = p.split(x, 1)
        out[a] = b
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--algod', default=None, help='algod data dir')
    ap.add_argument('-a', '--addr', default=None, help='algod host:port address')
    ap.add_argument('-t', '--token', default=None, help='algod API access token')
    ap.add_argument('--header', dest='headers', nargs='*', help='"Name: value" HTTP header (repeatable)')
    ap.add_argument('--verbose', default=False, action='store_true')
    ap.add_argument('-o', '--out', default=None, help='file to append json lines to')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    algorand_data = args.algod or os.getenv('ALGORAND_DATA')
    if not algorand_data and not (args.token and args.addr):
        sys.stderr.write('must specify algod data dir by $ALGORAND_DATA or -d/--algod; OR --a/--addr and -t/--token\n')
        sys.exit(1)

    bot = Fetcher(
        algorand_data,
        token=args.token,
        addr=args.addr,
        headers=header_list_to_dict(args.headers),
        outpath=args.out,
    )
    bot.loop()

if __name__ == '__main__':
    main()
