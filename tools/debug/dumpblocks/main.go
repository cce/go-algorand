// Copyright (C) 2019-2025 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/catchup"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/store/blockdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

var blockDBfile = flag.String("blockdb", "", "Block DB filename")
var numBlocks = flag.Int("numblocks", 10000, "Randomly sample this many blocks for training")
var startRound = flag.Int("start", 0, "Sample blocks starting at this round (inclusive)")
var endRound = flag.Int("end", 0, "Sample blocks ending at this round (inclusive)")
var outDir = flag.String("outdir", ".", "Write blocks to this directory")
var randSeed = flag.Int("seed", 0, "Random seed, otherwise will use time")
var createFlag = flag.Bool("create", false, "Create a new blockdb by downloading blocks from the network")
var serverAddress = flag.String("server", "", "Server address (host:port) to connect to for block downloads")
var genesisID = flag.String("genesis", "mainnet-v1.0", "Genesis ID for network connection")
var networkID = flag.String("network", "mainnet", "Network ID for network connection")

func getBlockToFile(db *sql.DB, rnd int64) error {
	var buf []byte
	err := db.QueryRow("SELECT blkdata FROM blocks WHERE rnd=?", rnd).Scan(&buf)
	if err != nil {
		return err
	}
	return os.WriteFile(fmt.Sprintf("%s/%d.block", *outDir, rnd), buf, 0644)
}

func usage() {
	flag.Usage()
	os.Exit(1)
}

// We don't need initBlocksDB anymore as we'll use BlockInit with the first block

// setupWebsocketNetwork creates a new websocket network for downloading blocks
func setupWebsocketNetwork(log logging.Logger) (network.GossipNode, error) {
	conf, _ := config.LoadConfigFromDisk("/dev/null")
	if *serverAddress != "" {
		conf.DNSBootstrapID = ""
	}

	n, err := network.NewWebsocketGossipNode(log,
		conf,
		[]string{*serverAddress},
		*genesisID,
		protocol.NetworkID(*networkID))
	if err != nil {
		return nil, fmt.Errorf("failed to create websocket network: %v", err)
	}

	err = n.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start network: %v", err)
	}

	return n, nil
}

// downloadBlocksAndCreateDB downloads blocks from the network and creates a new blockdb
func downloadBlocksAndCreateDB(log logging.Logger) error {
	// Setup network
	net, err := setupWebsocketNetwork(log)
	if err != nil {
		return err
	}
	defer net.Stop()

	// Wait for connections
	fmt.Println("Waiting for network connections...")
	time.Sleep(2 * time.Second)

	// Get peers
	peers := net.GetPeers(network.PeersConnectedOut)
	if len(peers) == 0 {
		return fmt.Errorf("no peers connected")
	}
	fmt.Printf("Connected to %d peers\n", len(peers))

	// Create a universal block fetcher
	fetcher := catchup.MakeUniversalBlockFetcher(log, net, config.GetDefaultLocal())

	// Create a new database (or reset an existing one)
	dbpath, err := filepath.Abs(*blockDBfile)
	if err != nil {
		return err
	}

	// Ensure directory exists
	dbdir := filepath.Dir(dbpath)
	err = os.MkdirAll(dbdir, 0755)
	if err != nil {
		return err
	}

	// Open or create the database
	uri := fmt.Sprintf("file:%s?_journal_mode=wal", dbpath)
	fmt.Println("Opening or creating database:", uri)
	db, err := sql.Open("sqlite3", uri)
	if err != nil {
		return err
	}
	// We'll close explicitly at the end of the function for better control
	// instead of using defer db.Close()

	// Initialize the database schema
	err = db.Ping()
	if err != nil {
		return err
	}

	_, err = db.Exec("DROP TABLE IF EXISTS blocks")
	if err != nil {
		return err
	}

	// We'll use BlockInit with the first block we download instead of initializing
	// the schema here, so we don't need initBlocksDB

	// Determine round range
	minRound := int64(*startRound)
	maxRound := int64(*endRound)
	if minRound <= 0 || maxRound <= 0 || maxRound < minRound {
		return fmt.Errorf("invalid round range: start=%d, end=%d", minRound, maxRound)
	}

	fmt.Printf("Downloading blocks from round %d to %d\n", minRound, maxRound)
	ctx := context.Background()

	// Initialize an empty blocks table first (needed for BlockCompleteCatchup to work)
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction for DB initialization: %v", err)
	}

	// Initialize the database schema without any blocks
	err = blockdb.BlockInit(tx, nil)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to initialize database: %v", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit DB initialization: %v", err)
	}

	// We'll initialize the staging area for the actual blocks when we get the first block

	// Download and store blocks
	for round := basics.Round(minRound); round <= basics.Round(maxRound); round++ {
		fmt.Printf("Fetching block %d...\n", round)

		// Try each peer until successful
		var block *bookkeeping.Block
		var cert *agreement.Certificate
		var fetchErr error
		for _, peer := range peers {
			block, cert, _, fetchErr = fetcher.FetchBlock(ctx, round, peer)
			if fetchErr == nil {
				break
			}
			// Handle peer address display differently based on peer type
			var peerAddr string
			if httpPeer, ok := peer.(network.HTTPPeer); ok {
				peerAddr = httpPeer.GetAddress()
			} else if unicastPeer, ok := peer.(network.UnicastPeer); ok {
				peerAddr = unicastPeer.GetAddress()
			} else {
				peerAddr = "<unknown>"
			}
			fmt.Printf("Error fetching from peer %s: %v\n", peerAddr, fetchErr)
		}

		if fetchErr != nil {
			return fmt.Errorf("failed to fetch block %d from any peer: %v", round, fetchErr)
		}

		// Begin a transaction for each block
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction for block %d: %v", round, err)
		}

		// For the first block, initialize the staging area
		if round == basics.Round(minRound) {
			fmt.Println("Initializing staging area...")
			err = blockdb.BlockStartCatchupStaging(tx, *block, *cert)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to initialize staging area: %v", err)
			}
		} else {
			// For subsequent blocks, use BlockPutStaging
			err = blockdb.BlockPutStaging(tx, *block, *cert)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to store block %d: %v", round, err)
			}
		}

		// Commit the transaction
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction for block %d: %v", round, err)
		}

		// We'll save blocks to files after completing the catchup process when the blocks table is properly populated
	}

	// Ensure the database is properly flushed and closed
	// Now complete the catchup process to move all blocks from staging to the main blocks table
	fmt.Println("Completing catchup process...")
	completeTx, completeErr := db.Begin()
	if completeErr != nil {
		return fmt.Errorf("failed to begin transaction for catchup completion: %v", completeErr)
	}

	completeErr = blockdb.BlockCompleteCatchup(completeTx)
	if completeErr != nil {
		completeTx.Rollback()
		return fmt.Errorf("failed to complete catchup: %v", completeErr)
	}

	if completeErr = completeTx.Commit(); completeErr != nil {
		return fmt.Errorf("failed to commit catchup completion: %v", completeErr)
	}

	fmt.Printf("Successfully downloaded and stored blocks %d to %d\n", minRound, maxRound)

	// Close the database connection
	closeErr := db.Close()
	if closeErr != nil {
		return fmt.Errorf("error closing database: %v", closeErr)
	}

	fmt.Println("Database closed successfully")
	return nil
}

func main() {
	flag.Parse()

	// Setup logging
	log := logging.Base()
	log.SetLevel(logging.Info)

	// Handle -create flag to download blocks from network
	if *createFlag {
		if *blockDBfile == "" {
			fmt.Println("-blockdb=file required")
			usage()
		}
		if *startRound == 0 || *endRound == 0 {
			fmt.Println("-start and -end rounds are required when using -create")
			usage()
		}

		err := downloadBlocksAndCreateDB(log)
		if err != nil {
			fmt.Printf("Error creating blockdb: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Original functionality for reading from an existing blockdb
	if *blockDBfile == "" {
		fmt.Println("-blockdb=file required")
		usage()
	}
	uri := fmt.Sprintf("file:%s?_journal_mode=wal", *blockDBfile)
	fmt.Println("Opening", uri)
	db, err := sql.Open("sqlite3", uri)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	seed := int64(*randSeed)
	if seed == 0 {
		seed = time.Now().UnixMicro()
	}
	rand.Seed(seed)

	var minRound, maxRound int64
	if *startRound != 0 {
		minRound = int64(*startRound)
	}
	if *endRound != 0 {
		maxRound = int64(*endRound)
	}
	if maxRound == 0 {
		err = db.QueryRow("SELECT MAX(rnd) FROM blocks").Scan(&maxRound)
		if err != nil {
			panic(err)
		}
	}
	if minRound == 0 {
		err = db.QueryRow("SELECT MIN(rnd) FROM blocks").Scan(&minRound)
		if err != nil {
			panic(err)
		}
	}

	N := maxRound - minRound
	if N <= 0 {
		panic("maxRound must be greater than minRound")
	}

	if N <= int64(*numBlocks) {
		// just get all blocks from minRound to maxRound
		fmt.Printf("Saving all blocks between round %d and %d\n", minRound, maxRound)
		for i := minRound; i <= maxRound; i++ {
			err = getBlockToFile(db, i)
			if err != nil {
				panic(err)
			}

		}
		os.Exit(0)
	}

	fmt.Printf("Loading %d random blocks between round %d and %d\n", *numBlocks, minRound, maxRound)
	for i := 0; i < *numBlocks; i++ {
		round := minRound + rand.Int63n(N) + 1
		err = getBlockToFile(db, round)
		if err != nil {
			panic(err)
		}
	}
}
