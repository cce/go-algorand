// Copyright (C) 2019-2021 Algorand, Inc.
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

package ledgercore

import (
	"reflect"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

// AccountData provides users of the Balances interface per-account data (like basics.AccountData)
// but without any maps containing AppParams, AppLocalState, AssetHolding, or AssetParams. This
// ensures that transaction evaluation must retrieve and mutate account, asset, and application data
// separately, to better support on-disk and in-memory schemas that do not store them together.
type AccountData struct {
	AccountBaseData
	VotingData
}

type AccountBaseData struct {
	Status             basics.Status
	MicroAlgos         basics.MicroAlgos
	RewardsBase        uint64
	RewardedMicroAlgos basics.MicroAlgos
	AuthAddr           basics.Address

	TotalAppSchema      basics.StateSchema
	TotalExtraAppPages  uint32
	TotalAppParams      uint32
	TotalAppLocalStates uint32
	TotalAssetParams    uint32
	TotalAssets         uint32
}

type VotingData struct {
	VoteID      crypto.OneTimeSignatureVerifier
	SelectionID crypto.VRFVerifier

	VoteFirstValid  basics.Round
	VoteLastValid   basics.Round
	VoteKeyDilution uint64

	// MicroAlgosWithReward basics.MicroAlgos
}

// ToAccountData returns ledgercore.AccountData from basics.AccountData
func ToAccountData(acct basics.AccountData) AccountData {
	return AccountData{
		AccountBaseData: AccountBaseData{
			Status:             acct.Status,
			MicroAlgos:         acct.MicroAlgos,
			RewardsBase:        acct.RewardsBase,
			RewardedMicroAlgos: acct.RewardedMicroAlgos,

			AuthAddr: acct.AuthAddr,

			TotalAppSchema:      acct.TotalAppSchema,
			TotalExtraAppPages:  acct.TotalExtraAppPages,
			TotalAssets:         uint32(len(acct.Assets)),
			TotalAppParams:      uint32(len(acct.AppParams)),
			TotalAppLocalStates: uint32(len(acct.AppLocalStates)),
		},
		VotingData: VotingData{
			VoteID:          acct.VoteID,
			SelectionID:     acct.SelectionID,
			VoteFirstValid:  acct.VoteFirstValid,
			VoteLastValid:   acct.VoteLastValid,
			VoteKeyDilution: acct.VoteKeyDilution,
		},
	}
}

// AssignAccountData assigns the contents of AccountData to the fields in basics.AccountData,
// but does not touch the AppParams, AppLocalState, AssetHolding, or AssetParams data.
func AssignAccountData(a *basics.AccountData, acct AccountData) {
	a.Status = acct.Status
	a.MicroAlgos = acct.MicroAlgos
	a.RewardsBase = acct.RewardsBase
	a.RewardedMicroAlgos = acct.RewardedMicroAlgos

	a.VoteID = acct.VoteID
	a.SelectionID = acct.SelectionID
	a.VoteFirstValid = acct.VoteFirstValid
	a.VoteLastValid = acct.VoteLastValid
	a.VoteKeyDilution = acct.VoteKeyDilution

	a.AuthAddr = acct.AuthAddr
	a.TotalAppSchema = acct.TotalAppSchema
	a.TotalExtraAppPages = acct.TotalExtraAppPages
}

func (ad AccountData) WithUpdatedRewards(proto config.ConsensusParams, rewardsLevel uint64) AccountData {
	u := basics.AccountData{
		Status:             ad.Status,
		MicroAlgos:         ad.MicroAlgos,
		RewardsBase:        ad.RewardsBase,
		RewardedMicroAlgos: ad.RewardedMicroAlgos,
	}
	u = u.WithUpdatedRewards(proto, rewardsLevel)

	ad.MicroAlgos = u.MicroAlgos
	ad.RewardsBase = u.RewardsBase
	ad.RewardedMicroAlgos = u.RewardedMicroAlgos
	return ad
}

// ClearOnlineState resets the account's fields to indicate that the account is an offline account
func (ad *AccountData) ClearOnlineState() {
	ad.Status = basics.Offline
	ad.VoteFirstValid = basics.Round(0)
	ad.VoteLastValid = basics.Round(0)
	ad.VoteKeyDilution = 0
	ad.VoteID = crypto.OneTimeSignatureVerifier{}
	ad.SelectionID = crypto.VRFVerifier{}
}

// MinBalance computes the minimum balance requirements for an account based on
// some consensus parameters. MinBalance should correspond roughly to how much
// storage the account is allowed to store on disk.
func (ad AccountData) MinBalance(proto *config.ConsensusParams) (res basics.MicroAlgos) {
	var min uint64

	// First, base MinBalance
	min = proto.MinBalance

	// MinBalance for each Asset
	assetCost := basics.MulSaturate(proto.MinBalance, uint64(ad.TotalAssets))
	min = basics.AddSaturate(min, assetCost)

	// Base MinBalance for each created application
	appCreationCost := basics.MulSaturate(proto.AppFlatParamsMinBalance, uint64(ad.TotalAppParams))
	min = basics.AddSaturate(min, appCreationCost)

	// Base MinBalance for each opted in application
	appOptInCost := basics.MulSaturate(proto.AppFlatOptInMinBalance, uint64(ad.TotalAppLocalStates))
	min = basics.AddSaturate(min, appOptInCost)

	// MinBalance for state usage measured by LocalStateSchemas and
	// GlobalStateSchemas
	schemaCost := ad.TotalAppSchema.MinBalance(proto)
	min = basics.AddSaturate(min, schemaCost.Raw)

	// MinBalance for each extra app program page
	extraAppProgramLenCost := basics.MulSaturate(proto.AppFlatParamsMinBalance, uint64(ad.TotalExtraAppPages))
	min = basics.AddSaturate(min, extraAppProgramLenCost)

	res.Raw = min
	return res
}

// IsZero checks if an AccountData value is the same as its zero value.
func (ad AccountData) IsZero() bool {
	return reflect.DeepEqual(ad, AccountData{})
}

func (ad AccountData) Money(proto config.ConsensusParams, rewardsLevel uint64) (money basics.MicroAlgos, rewards basics.MicroAlgos) {
	e := ad.WithUpdatedRewards(proto, rewardsLevel)
	return e.MicroAlgos, e.RewardedMicroAlgos
}

// OnlineAccountData calculates the online account data given an AccountData, by adding the rewards.
func (ad *AccountData) OnlineAccountData(proto config.ConsensusParams, rewardsLevel uint64) basics.OnlineAccountData {
	u := basics.AccountData{
		Status:             ad.Status,
		MicroAlgos:         ad.MicroAlgos,
		RewardsBase:        ad.RewardsBase,
		RewardedMicroAlgos: ad.RewardedMicroAlgos,
	}
	u = u.WithUpdatedRewards(proto, rewardsLevel)
	return basics.OnlineAccountData{
		MicroAlgosWithRewards: u.MicroAlgos,
		VoteID:                ad.VoteID,
		SelectionID:           ad.SelectionID,
		VoteFirstValid:        ad.VoteFirstValid,
		VoteLastValid:         ad.VoteLastValid,
		VoteKeyDilution:       ad.VoteKeyDilution,
	}
}
