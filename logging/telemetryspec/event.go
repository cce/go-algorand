// Copyright (C) 2019-2022 Algorand, Inc.
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

package telemetryspec

import (
	"time"
)

// Telemetry Events

// Event is the type used to identify telemetry events
// We want these to be stable and easy to find / document so we can create queries against them.
type Event string

// StartupEvent event
const StartupEvent Event = "Startup"

// StartupEventDetails contains details for the StartupEvent
type StartupEventDetails struct {
	Version      string
	CommitHash   string
	Branch       string
	Channel      string
	InstanceHash string
}

// HeartbeatEvent is sent periodically to indicate node is running
const HeartbeatEvent Event = "Heartbeat"

// HeartbeatEventDetails contains details for the StartupEvent
type HeartbeatEventDetails struct {
	Info struct {
		Version    string `json:"version"`
		VersionNum string `json:"version-num"`
		Channel    string `json:"channel"`
		Branch     string `json:"branch"`
		CommitHash string `json:"commit-hash"`
	} `json:"Metrics"` // backwards compatible name
	Metrics map[string]float64 `json:"m"`
}

// CatchupStartEvent event
const CatchupStartEvent Event = "CatchupStart"

// CatchupStartEventDetails contains details for the CatchupStartEvent
type CatchupStartEventDetails struct {
	StartRound uint64
}

// CatchupStopEvent event
const CatchupStopEvent Event = "CatchupStop"

// CatchupStopEventDetails contains details for the CatchupStopEvent
type CatchupStopEventDetails struct {
	StartRound uint64
	EndRound   uint64
	Time       time.Duration
	InitSync   bool
}

// ShutdownEvent event
const ShutdownEvent Event = "Shutdown"

// BlockAcceptedEvent event
const BlockAcceptedEvent Event = "BlockAccepted"

// BlockAcceptedEventDetails contains details for the BlockAcceptedEvent
type BlockAcceptedEventDetails struct {
	Address      string
	Hash         string
	Round        uint64
	ValidatedAt  time.Duration
	PreValidated bool
	PropBufLen   uint64
	VoteBufLen   uint64
}

// TopAccountsEvent event
const TopAccountsEvent Event = "TopAccounts"

// TopAccountEventDetails contains details for the BlockAcceptedEvent
type TopAccountEventDetails struct {
	Round              uint64
	OnlineAccounts     []map[string]interface{}
	OnlineCirculation  uint64
	OfflineCirculation uint64
}

// AccountRegisteredEvent event
const AccountRegisteredEvent Event = "AccountRegistered"

// AccountRegisteredEventDetails contains details for the AccountRegisteredEvent
type AccountRegisteredEventDetails struct {
	Address string
}

// PartKeyRegisteredEvent event
const PartKeyRegisteredEvent Event = "PartKeyRegistered"

// PartKeyRegisteredEventDetails contains details for the PartKeyRegisteredEvent
type PartKeyRegisteredEventDetails struct {
	Address    string
	FirstValid uint64
	LastValid  uint64
}

// BlockProposedEvent event
const BlockProposedEvent Event = "BlockProposed"

// BlockProposedEventDetails contains details for the BlockProposedEvent
type BlockProposedEventDetails struct {
	Address string
	Hash    string
	Round   uint64
	Period  uint64
	Step    uint64
}

// NewPeriodEvent event
const NewPeriodEvent Event = "NewPeriod"

// NewRoundPeriodDetails contains details for every new round or new period
// We explicitly log local time even though a timestamp is generated by logger.
type NewRoundPeriodDetails struct {
	OldRound  uint64
	OldPeriod uint64
	OldStep   uint64
	NewRound  uint64
	NewPeriod uint64
	NewStep   uint64
	LocalTime time.Time
}

// VoteSentEvent event
const VoteSentEvent Event = "VoteSent"

// VoteAcceptedEvent event
const VoteAcceptedEvent Event = "VoteAccepted"

// VoteEventDetails contains details for the VoteSentEvent
type VoteEventDetails struct {
	Address   string
	Hash      string
	Round     uint64
	Period    uint64
	Step      uint64
	Weight    uint64
	Recovered bool
}

// VoteRejectedEvent event
const VoteRejectedEvent Event = "VoteRejected"

// VoteRejectedEventDetails contains details for the VoteSentEvent
type VoteRejectedEventDetails struct {
	VoteEventDetails
	Reason string
}

// EquivocatedVoteEvent event
const EquivocatedVoteEvent Event = "EquivocatedVoteEvent"

// EquivocatedVoteEventDetails contains details for the EquivocatedVoteEvent
type EquivocatedVoteEventDetails struct {
	VoterAddress          string
	ProposalHash          string
	Round                 uint64
	Period                uint64
	Step                  uint64
	Weight                uint64
	PreviousProposalHash1 string
	PreviousProposalHash2 string
}

// ConnectPeerEvent event
const ConnectPeerEvent Event = "ConnectPeer"

// PeerEventDetails contains details for the ConnectPeerEvent
type PeerEventDetails struct {
	Address      string
	HostName     string
	Incoming     bool
	InstanceName string
	// Endpoint is the dialed-to address, for an outgoing connection. Not being used for incoming connection.
	Endpoint string `json:",omitempty"`
	// MessageDelay is the avarage relative message delay. Not being used for incoming connection.
	MessageDelay int64 `json:",omitempty"`
}

// ConnectPeerFailEvent event
const ConnectPeerFailEvent Event = "ConnectPeerFail"

// ConnectPeerFailEventDetails contains details for the ConnectPeerFailEvent
type ConnectPeerFailEventDetails struct {
	Address      string
	HostName     string
	Incoming     bool
	InstanceName string
	Reason       string
}

// DisconnectPeerEvent event
const DisconnectPeerEvent Event = "DisconnectPeer"

// DisconnectPeerEventDetails contains details for the DisconnectPeerEvent
type DisconnectPeerEventDetails struct {
	PeerEventDetails
	Reason string
}

// ErrorOutputEvent event
const ErrorOutputEvent Event = "ErrorOutput"

// ErrorOutputEventDetails contains details for ErrorOutputEvent
type ErrorOutputEventDetails struct {
	Output string
	Error  string
}

// DeadManTriggeredEvent event
const DeadManTriggeredEvent Event = "DeadManTriggered"

// DeadManTriggeredEventDetails contains details for DeadManTriggeredEvent
type DeadManTriggeredEventDetails struct {
	Timeout      int64
	CurrentBlock uint64
	GoRoutines   string
}

// BlockStatsEvent event
const BlockStatsEvent Event = "BlockStats"

// BlockStatsEventDetails contains details for BlockStatsEvent
type BlockStatsEventDetails struct {
	Hash                string
	OriginalProposer    string
	Round               uint64
	Transactions        uint64
	ActiveUsers         uint64
	AgreementDurationMs uint64
	NetworkDowntimeMs   uint64
}

// HTTPRequestEvent event
const HTTPRequestEvent Event = "HTTPRequest"

// HTTPRequestDetails contains details for the HTTPRequestEvent
// This should resemble the Common Log Format, as it's being used as the source data for generating it.
type HTTPRequestDetails struct {
	Client       string // The ip address of the remote
	InstanceName string // The node identifier
	Request      string // The request string, i.e. "GET /apache_pb.gif HTTP/1.0"
	StatusCode   uint64 // The response status code
	BodyLength   uint64 // The returned body length, in bytes
	UserAgent    string // The user-agent string ( if any )
}

// PeerConnectionsEvent event
const PeerConnectionsEvent Event = "PeerConnections"

// PeersConnectionDetails contains details for PeerConnectionsEvent
type PeersConnectionDetails struct {
	IncomingPeers []PeerConnectionDetails
	OutgoingPeers []PeerConnectionDetails
}

// PeerConnectionDetails contains details for PeerConnectionsEvent regarding a single peer ( either incoming or outgoing )
type PeerConnectionDetails struct {
	// Address is the IP address of the remote connected socket
	Address string
	// The HostName is the TelemetryGUID passed via the X-Algorand-TelId header during the http connection handshake.
	HostName string
	// InstanceName is the node-specific hashed instance name that was passed via X-Algorand-InstanceName header during the http connection handshake.
	InstanceName string
	// ConnectionDuration is the duration of the connection, in seconds.
	ConnectionDuration uint
	// Endpoint is the dialed-to address, for an outgoing connection. Not being used for incoming connection.
	Endpoint string `json:",omitempty"`
	// MessageDelay is the avarage relative message delay. Not being used for incoming connection.
	MessageDelay int64 `json:",omitempty"`
}

// CatchpointGenerationEvent event
const CatchpointGenerationEvent Event = "CatchpointGeneration"

// CatchpointGenerationEventDetails is generated once a catchpoint file is being created, and provide
// some statistics about that event.
type CatchpointGenerationEventDetails struct {
	// WritingDuration is the total elapsed time it took to write the catchpoint file.
	WritingDuration uint64
	// CPUTime is the single-core time spent waiting to the catchpoint file to be written.
	// this time excludes all the sleeping time taken, and represent the actual time it would
	// take if we were doing the writing on a dedicated process
	CPUTime uint64
	// BalancesWriteDuration is the time duration it took to write the balances portion
	// ( i.e. update the account balances + update the trie )
	BalancesWriteTime uint64
	// AccountsCount is the number of accounts that were written into the generated catchpoint file
	AccountsCount uint64
	// FileSize is the size of the catchpoint file, in bytes.
	FileSize uint64
	// CatchpointLabel is the catchpoint label for which the catchpoint file was generated.
	CatchpointLabel string
}

// BalancesAccountVacuumEvent event
const BalancesAccountVacuumEvent Event = "VacuumBalances"

// BalancesAccountVacuumEventDetails is generated once the balances account get vacuumed, and provides
// some statistics about that event.
type BalancesAccountVacuumEventDetails struct {
	// VacuumTimeNanoseconds is the total amount of time, in nanoseconds, that the vacuum operation took
	VacuumTimeNanoseconds int64
	// BeforeVacuumPageCount is the number of pages that the balances database had prior of running the vacuuming process.
	BeforeVacuumPageCount uint64
	// AfterVacuumPageCount is the number of pages that the balances database had after running the vacuuming process.
	AfterVacuumPageCount uint64
	// BeforeVacuumSpaceBytes is the number of bytes used by the database prior of running the vacuuming process.
	BeforeVacuumSpaceBytes uint64
	// AfterVacuumSpaceBytes is the number of bytes used by the database after running the vacuuming process.
	AfterVacuumSpaceBytes uint64
}
