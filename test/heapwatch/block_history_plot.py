#!/usr/bin/env python3
#
# Plot the output of test/heapwatch/{block_history.py,block_history_relays.py}

import base64
import statistics

from algosdk.encoding import msgpack
from matplotlib import pyplot as plt

def process(path):
    prevtime = None
    prevtc = 0
    prevts = None
    prevrnd = None
    mintxn = 9999999
    maxtxn = 0
    mindt = 999999
    maxdt = 0
    mintps = 999999
    maxtps = 0
    tpsv = []
    dtv = []
    txnv = []
    count = 0
    with open(path, 'rb') as fin:
        for line in fin:
            line = line.strip()
            row = msgpack.loads(base64.b64decode(line), strict_map_key=False)
            count += 1
            block = row['block']
            rnd = block.get('rnd',0)
            tc = block.get('tc', 0)
            ts = block.get('ts', 0) # timestamp recorded at algod, 1s resolution int
            _time = row['_time'] # timestamp recorded at client, 0.000001s resolution float
            if prevtime is not None:
                dt = _time - prevtime
                if dt < 1:
                    dt = ts - prevts
                dtxn = tc - prevtc
                tps = dtxn / dt
                mintxn = min(dtxn,mintxn)
                maxtxn = max(dtxn,maxtxn)
                mindt = min(dt,mindt)
                maxdt = max(dt,maxdt)
                mintps = min(tps,mintps)
                maxtps = max(tps,maxtps)
                tpsv.append(tps)
                dtv.append(dt)
                txnv.append(dtxn)
            prevrnd = rnd
            prevtc = tc
            prevts = ts
            prevtime = _time
    print('{} blocks, block txns [{}-{}], block seconds [{}-{}], tps [{}-{}]'.format(
        count,
        mintxn,maxtxn,
        mindt,maxdt,
        mintps,maxtps,
    ))

    # find the real start of the test
    start = 1
    for i in range(len(txnv)):
        if len(list(filter(lambda x: x > 100, txnv[i:i+5]))) == 5:
            start = i + 5
            break
    txmean = statistics.mean(txnv[start:])
    txstd = statistics.stdev(txnv[start:])
    end = len(txnv)
    for i in range(start,len(txnv)):
        if len(list(filter(lambda x: x > txmean-(txstd*2), txnv[i:i+5]))) < 4:
            print(i)
            end = i
            break

    print('core test rounds [{}:{}]'.format(start,end))
    print('block txns [{}-{}], block seconds [{}-{}], tps [{}-{}]'.format(
        min(txnv[start:end]), max(txnv[start:end]),
        min(dtv[start:end]), max(dtv[start:end]),
        min(tpsv[start:end]), max(tpsv[start:end]),
    ))
    print('long round times: {}'.format(' '.join(list(filter(lambda x: x >= 9,dtv[start:end])))))
    fig, (ax1, ax2, ax3) = plt.subplots(3)
    ax1.set_title('round time (seconds)')
    ax1.hist(list(filter(lambda x: x < 9,dtv[start:end])),bins=20)
    #plt.savefig(path + '_round_time_hist.svg', format='svg')
    #plt.savefig(path + '_round_time_hist.png', format='png')
    #plt.close()

    ax2.set_title('TPS')
    ax2.hist(tpsv[start:end],bins=20)
    #plt.savefig(path + '_tps_hist.svg', format='svg')
    #plt.savefig(path + '_tps_hist.png', format='png')
    #plt.close()

    ax3.set_title('txn/block')
    ax3.hist(txnv[start:end],bins=20)
    #plt.savefig(path + '_btxn_hist.svg', format='svg')
    #plt.savefig(path + '_btxn_hist.png', format='png')
    fig.tight_layout()
    plt.savefig(path + '_hist.svg', format='svg')
    plt.savefig(path + '_hist.png', format='png')

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('files', nargs='+')
    args = ap.parse_args()

    for fname in args.files:
        process(fname)

if __name__ == '__main__':
    main()
