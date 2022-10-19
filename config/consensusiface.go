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

package config

import (
	"time"

	"github.com/algorand/go-algorand/protocol"
)

// ConsensusParamsReader is an interface that provides read access to consensus parameters.
type ConsensusParamsReader interface {
	UpgradeVoteRounds() uint64
	UpgradeThreshold() uint64
	DefaultUpgradeWaitRounds() uint64
	MinUpgradeWaitRounds() uint64
	MaxUpgradeWaitRounds() uint64
	MaxVersionStringLen() int
	MaxTxnBytesPerBlock() int
	MaxTxnNoteBytes() int
	MaxTxnLife() uint64
	ApprovedUpgrades() map[protocol.ConsensusVersion]uint64
	SupportGenesisHash() bool
	RequireGenesisHash() bool
	DefaultKeyDilution() uint64
	MinBalance() uint64
	MinTxnFee() uint64
	EnableFeePooling() bool
	EnableAppCostPooling() bool
	RewardUnit() uint64
	RewardsRateRefreshInterval() uint64
	SeedLookback() uint64
	SeedRefreshInterval() uint64
	MaxBalLookback() uint64
	NumProposers() uint64
	SoftCommitteeSize() uint64
	SoftCommitteeThreshold() uint64
	CertCommitteeSize() uint64
	CertCommitteeThreshold() uint64
	NextCommitteeSize() uint64
	NextCommitteeThreshold() uint64
	LateCommitteeSize() uint64
	LateCommitteeThreshold() uint64
	RedoCommitteeSize() uint64
	RedoCommitteeThreshold() uint64
	DownCommitteeSize() uint64
	DownCommitteeThreshold() uint64
	AgreementFilterTimeout() time.Duration
	AgreementFilterTimeoutPeriod0() time.Duration
	FastRecoveryLambda() time.Duration
	PaysetCommit() PaysetCommitType
	MaxTimestampIncrement() int64
	SupportSignedTxnInBlock() bool
	ForceNonParticipatingFeeSink() bool
	ApplyData() bool
	RewardsInApplyData() bool
	CredentialDomainSeparationEnabled() bool
	SupportBecomeNonParticipatingTransactions() bool
	PendingResidueRewards() bool
	Asset() bool
	MaxAssetsPerAccount() int
	MaxAssetNameBytes() int
	MaxAssetUnitNameBytes() int
	MaxAssetURLBytes() int
	TxnCounter() bool
	SupportTxGroups() bool
	MaxTxGroupSize() int
	SupportTransactionLeases() bool
	FixTransactionLeases() bool
	LogicSigVersion() uint64
	LogicSigMaxSize() uint64
	LogicSigMaxCost() uint64
	MaxAssetDecimals() uint32
	SupportRekeying() bool
	Application() bool
	MaxAppArgs() int
	MaxAppTotalArgLen() int
	MaxAppProgramLen() int
	MaxAppTotalProgramLen() int
	MaxExtraAppProgramPages() int
	MaxAppTxnAccounts() int
	MaxAppTxnForeignApps() int
	MaxAppTxnForeignAssets() int
	MaxAppTotalTxnReferences() int
	MaxAppProgramCost() int
	MaxAppKeyLen() int
	MaxAppBytesValueLen() int
	MaxAppSumKeyValueLens() int
	MaxInnerTransactions() int
	EnableInnerTransactionPooling() bool
	IsolateClearState() bool
	MinInnerApplVersion() uint64
	MaxAppsCreated() int
	MaxAppsOptedIn() int
	AppFlatParamsMinBalance() uint64
	AppFlatOptInMinBalance() uint64
	SchemaMinBalancePerEntry() uint64
	SchemaUintMinBalance() uint64
	SchemaBytesMinBalance() uint64
	MaxLocalSchemaEntries() uint64
	MaxGlobalSchemaEntries() uint64
	MaximumMinimumBalance() uint64
	StateProofInterval() uint64
	StateProofTopVoters() uint64
	StateProofVotersLookback() uint64
	StateProofWeightThreshold() uint32
	StateProofStrengthTarget() uint64
	StateProofMaxRecoveryIntervals() uint64
	StateProofExcludeTotalWeightWithRewards() bool
	EnableAssetCloseAmount() bool
	InitialRewardsRateCalculation() bool
	NoEmptyLocalDeltas() bool
	EnableKeyregCoherencyCheck() bool
	EnableExtraPagesOnAppUpdate() bool
	MaxProposedExpiredOnlineAccounts() int
	EnableAccountDataResourceSeparation() bool
	RewardsCalculationFix() bool
	EnableStateProofKeyregCheck() bool
	MaxKeyregValidPeriod() uint64
	UnifyInnerTxIDs() bool
	EnableSHA256TxnCommitmentHeader() bool
	CatchpointLookback() uint64
	DeeperBlockHeaderHistory() uint64
	EnableOnlineAccountCatchpoints() bool
	UnfundedSenders() bool
}

// ConsensusParamsRef provides readers for a reference to ConsensusParams.
type ConsensusParamsRef struct {
	params *ConsensusParams
}

func (c *ConsensusParamsRef) UpgradeVoteRounds() uint64 {
	return c.params.UpgradeVoteRounds
}

func (c *ConsensusParamsRef) UpgradeThreshold() uint64 {
	return c.params.UpgradeThreshold
}

func (c *ConsensusParamsRef) DefaultUpgradeWaitRounds() uint64 {
	return c.params.DefaultUpgradeWaitRounds
}

func (c *ConsensusParamsRef) MinUpgradeWaitRounds() uint64 {
	return c.params.MinUpgradeWaitRounds
}

func (c *ConsensusParamsRef) MaxUpgradeWaitRounds() uint64 {
	return c.params.MaxUpgradeWaitRounds
}

func (c *ConsensusParamsRef) MaxVersionStringLen() int {
	return c.params.MaxVersionStringLen
}

func (c *ConsensusParamsRef) MaxTxnBytesPerBlock() int {
	return c.params.MaxTxnBytesPerBlock
}

func (c *ConsensusParamsRef) MaxTxnNoteBytes() int {
	return c.params.MaxTxnNoteBytes
}

func (c *ConsensusParamsRef) MaxTxnLife() uint64 {
	return c.params.MaxTxnLife
}

func (c *ConsensusParamsRef) ApprovedUpgrades() map[protocol.ConsensusVersion]uint64 {
	return c.params.ApprovedUpgrades
}

func (c *ConsensusParamsRef) SupportGenesisHash() bool {
	return c.params.SupportGenesisHash
}

func (c *ConsensusParamsRef) RequireGenesisHash() bool {
	return c.params.RequireGenesisHash
}

func (c *ConsensusParamsRef) DefaultKeyDilution() uint64 {
	return c.params.DefaultKeyDilution
}

func (c *ConsensusParamsRef) MinBalance() uint64 {
	return c.params.MinBalance
}

func (c *ConsensusParamsRef) MinTxnFee() uint64 {
	return c.params.MinTxnFee
}

func (c *ConsensusParamsRef) EnableFeePooling() bool {
	return c.params.EnableFeePooling
}

func (c *ConsensusParamsRef) EnableAppCostPooling() bool {
	return c.params.EnableAppCostPooling
}

func (c *ConsensusParamsRef) RewardUnit() uint64 {
	return c.params.RewardUnit
}

func (c *ConsensusParamsRef) RewardsRateRefreshInterval() uint64 {
	return c.params.RewardsRateRefreshInterval
}

func (c *ConsensusParamsRef) SeedLookback() uint64 {
	return c.params.SeedLookback
}

func (c *ConsensusParamsRef) SeedRefreshInterval() uint64 {
	return c.params.SeedRefreshInterval
}

func (c *ConsensusParamsRef) MaxBalLookback() uint64 {
	return c.params.MaxBalLookback
}

func (c *ConsensusParamsRef) NumProposers() uint64 {
	return c.params.NumProposers
}

func (c *ConsensusParamsRef) SoftCommitteeSize() uint64 {
	return c.params.SoftCommitteeSize
}

func (c *ConsensusParamsRef) SoftCommitteeThreshold() uint64 {
	return c.params.SoftCommitteeThreshold
}

func (c *ConsensusParamsRef) CertCommitteeSize() uint64 {
	return c.params.CertCommitteeSize
}

func (c *ConsensusParamsRef) CertCommitteeThreshold() uint64 {
	return c.params.CertCommitteeThreshold
}

func (c *ConsensusParamsRef) NextCommitteeSize() uint64 {
	return c.params.NextCommitteeSize
}

func (c *ConsensusParamsRef) NextCommitteeThreshold() uint64 {
	return c.params.NextCommitteeThreshold
}

func (c *ConsensusParamsRef) LateCommitteeSize() uint64 {
	return c.params.LateCommitteeSize
}

func (c *ConsensusParamsRef) LateCommitteeThreshold() uint64 {
	return c.params.LateCommitteeThreshold
}

func (c *ConsensusParamsRef) RedoCommitteeSize() uint64 {
	return c.params.RedoCommitteeSize
}

func (c *ConsensusParamsRef) RedoCommitteeThreshold() uint64 {
	return c.params.RedoCommitteeThreshold
}

func (c *ConsensusParamsRef) DownCommitteeSize() uint64 {
	return c.params.DownCommitteeSize
}

func (c *ConsensusParamsRef) DownCommitteeThreshold() uint64 {
	return c.params.DownCommitteeThreshold
}

func (c *ConsensusParamsRef) AgreementFilterTimeout() time.Duration {
	return c.params.AgreementFilterTimeout
}

func (c *ConsensusParamsRef) AgreementFilterTimeoutPeriod0() time.Duration {
	return c.params.AgreementFilterTimeoutPeriod0
}

func (c *ConsensusParamsRef) FastRecoveryLambda() time.Duration {
	return c.params.FastRecoveryLambda
}

func (c *ConsensusParamsRef) PaysetCommit() PaysetCommitType {
	return c.params.PaysetCommit
}

func (c *ConsensusParamsRef) MaxTimestampIncrement() int64 {
	return c.params.MaxTimestampIncrement
}

func (c *ConsensusParamsRef) SupportSignedTxnInBlock() bool {
	return c.params.SupportSignedTxnInBlock
}

func (c *ConsensusParamsRef) ForceNonParticipatingFeeSink() bool {
	return c.params.ForceNonParticipatingFeeSink
}

func (c *ConsensusParamsRef) ApplyData() bool {
	return c.params.ApplyData
}

func (c *ConsensusParamsRef) RewardsInApplyData() bool {
	return c.params.RewardsInApplyData
}

func (c *ConsensusParamsRef) CredentialDomainSeparationEnabled() bool {
	return c.params.CredentialDomainSeparationEnabled
}

func (c *ConsensusParamsRef) SupportBecomeNonParticipatingTransactions() bool {
	return c.params.SupportBecomeNonParticipatingTransactions
}

func (c *ConsensusParamsRef) PendingResidueRewards() bool {
	return c.params.PendingResidueRewards
}

func (c *ConsensusParamsRef) Asset() bool {
	return c.params.Asset
}

func (c *ConsensusParamsRef) MaxAssetsPerAccount() int {
	return c.params.MaxAssetsPerAccount
}

func (c *ConsensusParamsRef) MaxAssetNameBytes() int {
	return c.params.MaxAssetNameBytes
}

func (c *ConsensusParamsRef) MaxAssetUnitNameBytes() int {
	return c.params.MaxAssetUnitNameBytes
}

func (c *ConsensusParamsRef) MaxAssetURLBytes() int {
	return c.params.MaxAssetURLBytes
}

func (c *ConsensusParamsRef) TxnCounter() bool {
	return c.params.TxnCounter
}

func (c *ConsensusParamsRef) SupportTxGroups() bool {
	return c.params.SupportTxGroups
}

func (c *ConsensusParamsRef) MaxTxGroupSize() int {
	return c.params.MaxTxGroupSize
}

func (c *ConsensusParamsRef) SupportTransactionLeases() bool {
	return c.params.SupportTransactionLeases
}

func (c *ConsensusParamsRef) FixTransactionLeases() bool {
	return c.params.FixTransactionLeases
}

func (c *ConsensusParamsRef) LogicSigVersion() uint64 {
	return c.params.LogicSigVersion
}

func (c *ConsensusParamsRef) LogicSigMaxSize() uint64 {
	return c.params.LogicSigMaxSize
}

func (c *ConsensusParamsRef) LogicSigMaxCost() uint64 {
	return c.params.LogicSigMaxCost
}

func (c *ConsensusParamsRef) MaxAssetDecimals() uint32 {
	return c.params.MaxAssetDecimals
}

func (c *ConsensusParamsRef) SupportRekeying() bool {
	return c.params.SupportRekeying
}

func (c *ConsensusParamsRef) Application() bool {
	return c.params.Application
}

func (c *ConsensusParamsRef) MaxAppArgs() int {
	return c.params.MaxAppArgs
}

func (c *ConsensusParamsRef) MaxAppTotalArgLen() int {
	return c.params.MaxAppTotalArgLen
}

func (c *ConsensusParamsRef) MaxAppProgramLen() int {
	return c.params.MaxAppProgramLen
}

func (c *ConsensusParamsRef) MaxAppTotalProgramLen() int {
	return c.params.MaxAppTotalProgramLen
}

func (c *ConsensusParamsRef) MaxExtraAppProgramPages() int {
	return c.params.MaxExtraAppProgramPages
}

func (c *ConsensusParamsRef) MaxAppTxnAccounts() int {
	return c.params.MaxAppTxnAccounts
}

func (c *ConsensusParamsRef) MaxAppTxnForeignApps() int {
	return c.params.MaxAppTxnForeignApps
}

func (c *ConsensusParamsRef) MaxAppTxnForeignAssets() int {
	return c.params.MaxAppTxnForeignAssets
}

func (c *ConsensusParamsRef) MaxAppTotalTxnReferences() int {
	return c.params.MaxAppTotalTxnReferences
}

func (c *ConsensusParamsRef) MaxAppProgramCost() int {
	return c.params.MaxAppProgramCost
}

func (c *ConsensusParamsRef) MaxAppKeyLen() int {
	return c.params.MaxAppKeyLen
}

func (c *ConsensusParamsRef) MaxAppBytesValueLen() int {
	return c.params.MaxAppBytesValueLen
}

func (c *ConsensusParamsRef) MaxAppSumKeyValueLens() int {
	return c.params.MaxAppSumKeyValueLens
}

func (c *ConsensusParamsRef) MaxInnerTransactions() int {
	return c.params.MaxInnerTransactions
}

func (c *ConsensusParamsRef) EnableInnerTransactionPooling() bool {
	return c.params.EnableInnerTransactionPooling
}

func (c *ConsensusParamsRef) IsolateClearState() bool {
	return c.params.IsolateClearState
}

func (c *ConsensusParamsRef) MinInnerApplVersion() uint64 {
	return c.params.MinInnerApplVersion
}

func (c *ConsensusParamsRef) MaxAppsCreated() int {
	return c.params.MaxAppsCreated
}

func (c *ConsensusParamsRef) MaxAppsOptedIn() int {
	return c.params.MaxAppsOptedIn
}

func (c *ConsensusParamsRef) AppFlatParamsMinBalance() uint64 {
	return c.params.AppFlatParamsMinBalance
}

func (c *ConsensusParamsRef) AppFlatOptInMinBalance() uint64 {
	return c.params.AppFlatOptInMinBalance
}

func (c *ConsensusParamsRef) SchemaMinBalancePerEntry() uint64 {
	return c.params.SchemaMinBalancePerEntry
}

func (c *ConsensusParamsRef) SchemaUintMinBalance() uint64 {
	return c.params.SchemaUintMinBalance
}

func (c *ConsensusParamsRef) SchemaBytesMinBalance() uint64 {
	return c.params.SchemaBytesMinBalance
}

func (c *ConsensusParamsRef) MaxLocalSchemaEntries() uint64 {
	return c.params.MaxLocalSchemaEntries
}

func (c *ConsensusParamsRef) MaxGlobalSchemaEntries() uint64 {
	return c.params.MaxGlobalSchemaEntries
}

func (c *ConsensusParamsRef) MaximumMinimumBalance() uint64 {
	return c.params.MaximumMinimumBalance
}

func (c *ConsensusParamsRef) StateProofInterval() uint64 {
	return c.params.StateProofInterval
}

func (c *ConsensusParamsRef) StateProofTopVoters() uint64 {
	return c.params.StateProofTopVoters
}

func (c *ConsensusParamsRef) StateProofVotersLookback() uint64 {
	return c.params.StateProofVotersLookback
}

func (c *ConsensusParamsRef) StateProofWeightThreshold() uint32 {
	return c.params.StateProofWeightThreshold
}

func (c *ConsensusParamsRef) StateProofStrengthTarget() uint64 {
	return c.params.StateProofStrengthTarget
}

func (c *ConsensusParamsRef) StateProofMaxRecoveryIntervals() uint64 {
	return c.params.StateProofMaxRecoveryIntervals
}

func (c *ConsensusParamsRef) StateProofExcludeTotalWeightWithRewards() bool {
	return c.params.StateProofExcludeTotalWeightWithRewards
}

func (c *ConsensusParamsRef) EnableAssetCloseAmount() bool {
	return c.params.EnableAssetCloseAmount
}

func (c *ConsensusParamsRef) InitialRewardsRateCalculation() bool {
	return c.params.InitialRewardsRateCalculation
}

func (c *ConsensusParamsRef) NoEmptyLocalDeltas() bool {
	return c.params.NoEmptyLocalDeltas
}

func (c *ConsensusParamsRef) EnableKeyregCoherencyCheck() bool {
	return c.params.EnableKeyregCoherencyCheck
}

func (c *ConsensusParamsRef) EnableExtraPagesOnAppUpdate() bool {
	return c.params.EnableExtraPagesOnAppUpdate
}

func (c *ConsensusParamsRef) MaxProposedExpiredOnlineAccounts() int {
	return c.params.MaxProposedExpiredOnlineAccounts
}

func (c *ConsensusParamsRef) EnableAccountDataResourceSeparation() bool {
	return c.params.EnableAccountDataResourceSeparation
}

func (c *ConsensusParamsRef) RewardsCalculationFix() bool {
	return c.params.RewardsCalculationFix
}

func (c *ConsensusParamsRef) EnableStateProofKeyregCheck() bool {
	return c.params.EnableStateProofKeyregCheck
}

func (c *ConsensusParamsRef) MaxKeyregValidPeriod() uint64 {
	return c.params.MaxKeyregValidPeriod
}

func (c *ConsensusParamsRef) UnifyInnerTxIDs() bool {
	return c.params.UnifyInnerTxIDs
}

func (c *ConsensusParamsRef) EnableSHA256TxnCommitmentHeader() bool {
	return c.params.EnableSHA256TxnCommitmentHeader
}

func (c *ConsensusParamsRef) CatchpointLookback() uint64 {
	return c.params.CatchpointLookback
}

func (c *ConsensusParamsRef) DeeperBlockHeaderHistory() uint64 {
	return c.params.DeeperBlockHeaderHistory
}

func (c *ConsensusParamsRef) EnableOnlineAccountCatchpoints() bool {
	return c.params.EnableOnlineAccountCatchpoints
}

func (c *ConsensusParamsRef) UnfundedSenders() bool {
	return c.params.UnfundedSenders
}
