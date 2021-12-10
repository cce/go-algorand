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
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
)

const (
	accountArrayEntrySize                 = uint64(232) // Measured by BenchmarkBalanceRecord
	accountMapCacheEntrySize              = uint64(64)  // Measured by BenchmarkAcctCache
	txleasesEntrySize                     = uint64(112) // Measured by BenchmarkTxLeases
	creatablesEntrySize                   = uint64(100) // Measured by BenchmarkCreatables
	stateDeltaTargetOptimizationThreshold = uint64(50000000)
)

// ModifiedCreatable defines the changes to a single single creatable state
type ModifiedCreatable struct {
	// Type of the creatable: app or asset
	Ctype basics.CreatableType

	// Created if true, deleted if false
	Created bool

	// creator of the app/asset
	Creator basics.Address

	// Keeps track of how many times this app/asset appears in
	// accountUpdates.creatableDeltas
	Ndeltas int
}

// AccountAsset is used as a map key.
type AccountAsset struct {
	Address basics.Address
	Asset   basics.AssetIndex
}

// AccountApp is used as a map key.
type AccountApp struct {
	Address basics.Address
	App     basics.AppIndex
}

// A Txlease is a transaction (sender, lease) pair which uniquely specifies a
// transaction lease.
type Txlease struct {
	Sender basics.Address
	Lease  [32]byte
}

// StateDelta describes the delta between a given round to the previous round
type StateDelta struct {
	// modified accounts
	// Accts AccountDeltas

	// modified new accounts
	NewAccts NewAccountDeltas

	// new Txids for the txtail and TxnCounter, mapped to txn.LastValid
	Txids map[transactions.Txid]basics.Round

	// new txleases for the txtail mapped to expiration
	Txleases map[Txlease]basics.Round

	// new creatables creator lookup table
	Creatables map[basics.CreatableIndex]ModifiedCreatable

	// new block header; read-only
	Hdr *bookkeeping.BlockHeader

	// next round for which we expect a compact cert.
	// zero if no compact cert is expected.
	CompactCertNext basics.Round

	// previous block timestamp
	PrevTimestamp int64

	// Modified local creatable states. The value is true if the creatable local state
	// is created and false if deleted. Used by indexer.
	ModifiedAssetHoldings  map[AccountAsset]bool
	ModifiedAppLocalStates map[AccountApp]bool

	// initial hint for allocating data structures for StateDelta
	initialTransactionsCount int

	// The account totals reflecting the changes in this StateDelta object.
	Totals AccountTotals
}

// AccountDeltas stores ordered accounts and allows fast lookup by address
// type AccountDeltas struct {
// 	// Actual data. If an account is deleted, `accts` contains a balance record
// 	// with empty `AccountData`.
// 	accts []basics.BalanceRecord
// 	// cache for addr to deltas index resolution
// 	acctsCache map[basics.Address]int
// }

// NewBalanceRecord stores a balance record using the smaller ledgercore.AccountData type
type NewBalanceRecord struct {
	Addr basics.Address

	AccountData
}

// NewAccountDeltas stores ordered accounts and allows fast lookup by address
type NewAccountDeltas struct {
	// Actual data. If an account is deleted, `accts` contains a balance record
	// with empty `AccountData`.
	accts []NewBalanceRecord
	// cache for addr to deltas index resolution
	acctsCache map[basics.Address]int

	appParams      map[AccountApp]*basics.AppParams
	appLocalStates map[AccountApp]*basics.AppLocalState
	assetParams    map[AccountAsset]*basics.AssetParams
	assets         map[AccountAsset]*basics.AssetHolding
}

// MakeStateDelta creates a new instance of StateDelta.
// hint is amount of transactions for evaluation, 2 * hint is for sender and receiver balance records.
// This does not play well for AssetConfig and ApplicationCall transactions on scale
func MakeStateDelta(hdr *bookkeeping.BlockHeader, prevTimestamp int64, hint int, compactCertNext basics.Round) StateDelta {
	return StateDelta{
		// Accts: AccountDeltas{
		// 	accts:      make([]basics.BalanceRecord, 0, hint*2),
		// 	acctsCache: make(map[basics.Address]int, hint*2),
		// },
		NewAccts: NewAccountDeltas{
			accts:      make([]NewBalanceRecord, 0, hint*2),
			acctsCache: make(map[basics.Address]int, hint*2),

			appParams:      make(map[AccountApp]*basics.AppParams),
			appLocalStates: make(map[AccountApp]*basics.AppLocalState),
			assetParams:    make(map[AccountAsset]*basics.AssetParams),
			assets:         make(map[AccountAsset]*basics.AssetHolding),
		},
		Txids:    make(map[transactions.Txid]basics.Round, hint),
		Txleases: make(map[Txlease]basics.Round, hint),
		// asset or application creation are considered as rare events so do not pre-allocate space for them
		Creatables:               make(map[basics.CreatableIndex]ModifiedCreatable),
		Hdr:                      hdr,
		CompactCertNext:          compactCertNext,
		PrevTimestamp:            prevTimestamp,
		ModifiedAssetHoldings:    make(map[AccountAsset]bool),
		ModifiedAppLocalStates:   make(map[AccountApp]bool),
		initialTransactionsCount: hint,
	}
}

// // Get lookups AccountData by address
// func (ad *AccountDeltas) Get(addr basics.Address) (basics.AccountData, bool) {
// 	idx, ok := ad.acctsCache[addr]
// 	if !ok {
// 		return basics.AccountData{}, false
// 	}
// 	return ad.accts[idx].AccountData, true
// }

// GetData lookups AccountData by address
func (ad NewAccountDeltas) GetData(addr basics.Address) (AccountData, bool) {
	idx, ok := ad.acctsCache[addr]
	if !ok {
		return AccountData{}, false
	}
	return ad.accts[idx].AccountData, true
}

// GetAppParams returns the params for a given address and app index, or false if it does not exist.
func (ad NewAccountDeltas) GetAppParams(addr basics.Address, aidx basics.AppIndex) (*basics.AppParams, bool) {
	params, ok := ad.appParams[AccountApp{addr, aidx}]
	return params, ok
	// if !ok {
	// 	return basics.AppParams{}, false
	// }
	// return *params, true
}

// GetAssetParams returns the asset params for a given address and asset index, or false if it does not exist.
func (ad NewAccountDeltas) GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (*basics.AssetParams, bool) {
	params, ok := ad.assetParams[AccountAsset{addr, aidx}]
	return params, ok
	// if !ok || params == nil {
	// 	return basics.AssetParams{}, false
	// }
	// return *params, true
}

// GetAppLocalState returns the local state for a given address and app index, or false if it does not exist.
func (ad NewAccountDeltas) GetAppLocalState(addr basics.Address, aidx basics.AppIndex) (*basics.AppLocalState, bool) {
	ls, ok := ad.appLocalStates[AccountApp{addr, aidx}]
	return ls, ok
	// if !ok || ls == nil {
	// 	return basics.AppLocalState{}, false
	// }
	// return *ls, true
}

// GetAppLocalState returns the holding for a given address and asset index, or false if it does not exist.
func (ad NewAccountDeltas) GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (*basics.AssetHolding, bool) {
	holding, ok := ad.assets[AccountAsset{addr, aidx}]
	return holding, ok
	// if !ok || holding == nil {
	// 	return basics.AssetHolding{}, false
	// }
	// return *holding, true
}

// ModifiedAccounts returns list of addresses of modified accounts
func (ad NewAccountDeltas) ModifiedAccounts() []basics.Address {
	result := make([]basics.Address, len(ad.accts))
	for i := 0; i < len(ad.accts); i++ {
		result[i] = ad.accts[i].Addr
	}

	// consistency check: ensure all addresses in params/holdings/states are also in base account
	for aapp := range ad.appParams {
		if _, ok := ad.acctsCache[aapp.Address]; !ok {
			panic(fmt.Sprintf("account app param delta: addr %s not in base account", aapp.Address))
		}
	}
	for aapp := range ad.appLocalStates {
		if _, ok := ad.acctsCache[aapp.Address]; !ok {
			panic(fmt.Sprintf("account app state delta: addr %s not in base account", aapp.Address))
		}
	}
	for aapp := range ad.assetParams {
		if _, ok := ad.acctsCache[aapp.Address]; !ok {
			panic(fmt.Sprintf("account asset param delta: addr %s not in base account", aapp.Address))
		}
	}
	for aapp := range ad.assets {
		if _, ok := ad.acctsCache[aapp.Address]; !ok {
			panic(fmt.Sprintf("account asset holding delta: addr %s not in base account", aapp.Address))
		}
	}

	return result
}

// MergeAccounts applies other accounts into this StateDelta accounts
func (ad *NewAccountDeltas) MergeAccounts(other NewAccountDeltas) {
	for new := range other.accts {
		addr := other.accts[new].Addr
		acct := other.accts[new].AccountData
		ad.Upsert(addr, acct)
	}

	for aapp, params := range other.appParams {
		ad.UpsertAppParams(aapp.Address, aapp.App, params)
	}
	for aapp, state := range other.appLocalStates {
		ad.UpsertAppLocalState(aapp.Address, aapp.App, state)
	}
	for aapp, params := range other.assetParams {
		ad.UpsertAssetParams(aapp.Address, aapp.Asset, params)
	}
	for aapp, holding := range other.assets {
		ad.UpsertAssetHolding(aapp.Address, aapp.Asset, holding)
	}
}

// Clone copies all map in NewAccountDeltas but does not reallocates inner arrays like addresses or metadata inside asset params
func (ad NewAccountDeltas) Clone() NewAccountDeltas {
	clone := NewAccountDeltas{
		accts:      make([]NewBalanceRecord, len(ad.accts)),
		acctsCache: make(map[basics.Address]int, len(ad.acctsCache)),

		appParams:      make(map[AccountApp]*basics.AppParams, len(ad.appParams)),
		appLocalStates: make(map[AccountApp]*basics.AppLocalState, len(ad.appLocalStates)),
		assetParams:    make(map[AccountAsset]*basics.AssetParams, len(ad.assetParams)),
		assets:         make(map[AccountAsset]*basics.AssetHolding, len(ad.assets)),
	}

	for idx := range ad.accts {
		clone.accts[idx] = ad.accts[idx]
	}

	for addr, idx := range ad.acctsCache {
		clone.acctsCache[addr] = idx
	}

	for aapp, val := range ad.appParams {
		if val == nil {
			clone.appParams[aapp] = nil
		} else {
			cp := *val
			clone.appParams[aapp] = &cp
		}
	}

	for aapp, val := range ad.appLocalStates {
		if val == nil {
			clone.appLocalStates[aapp] = nil
		} else {
			cp := *val
			clone.appLocalStates[aapp] = &cp
		}
	}

	for aapp, val := range ad.assetParams {
		if val == nil {
			clone.assetParams[aapp] = nil
		} else {
			cp := *val
			clone.assetParams[aapp] = &cp
		}
	}

	for aapp, val := range ad.assets {
		if val == nil {
			clone.assets[aapp] = nil
		} else {
			cp := *val
			clone.assets[aapp] = &cp
		}
	}

	return clone
}

// GetResource looks up a pair of app or asset resources, given its index and type.
func (ad NewAccountDeltas) GetResource(addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (ret AccountResource, ok bool) {
	ret.CreatableIndex = aidx
	ret.CreatableType = ctype
	switch ctype {
	case basics.AssetCreatable:
		aa := AccountAsset{addr, basics.AssetIndex(aidx)}
		params, okParams := ad.assetParams[aa]
		if okParams {
			ret.AssetParam = params
		}
		holding, okHolding := ad.assets[aa]
		if okHolding {
			ret.AssetHolding = holding
		}
		return ret, okHolding || okParams
	case basics.AppCreatable:
		aa := AccountApp{addr, basics.AppIndex(aidx)}
		params, okParams := ad.appParams[aa]
		if okParams {
			ret.AppParams = params
		}
		localState, okLocalState := ad.appLocalStates[aa]
		if okLocalState {
			ret.AppLocalState = localState
		}
		return ret, okLocalState || okParams
	}
	return ret, false
}

// MergeInMatchingAccounts adds data from other for matching addresses.
// It assumes ad is newer than other
func (ad NewAccountDeltas) MergeInMatchingAccounts(other NewAccountDeltas) {
	// do not update accts/acctsCache because ad is newer

	// find missing params/holdings/states to add into newer delta
	for aapp, val := range other.appParams {
		addr := aapp.Address
		if _, ok := ad.acctsCache[addr]; ok {
			// address is in newer delta, add params if needed
			if _, ok := ad.appParams[aapp]; !ok {
				if val == nil {
					ad.appParams[aapp] = nil
				} else {
					cp := *val
					ad.appParams[aapp] = &cp
				}
			}
		}
	}

	for aapp, val := range other.appLocalStates {
		addr := aapp.Address
		if _, ok := ad.acctsCache[addr]; ok {
			// address is in newer delta, add params if needed
			if _, ok := ad.appLocalStates[aapp]; !ok {
				if val == nil {
					ad.appLocalStates[aapp] = nil
				} else {
					cp := *val
					ad.appLocalStates[aapp] = &cp
				}
			}
		}
	}

	for aapp, val := range other.assetParams {
		addr := aapp.Address
		if _, ok := ad.acctsCache[addr]; ok {
			// address is in newer delta, add params if needed
			if _, ok := ad.assetParams[aapp]; !ok {
				if val == nil {
					ad.assetParams[aapp] = nil
				} else {
					cp := *val
					ad.assetParams[aapp] = &cp
				}
			}
		}
	}

	for aapp, val := range other.assets {
		addr := aapp.Address
		if _, ok := ad.acctsCache[addr]; ok {
			// address is in newer delta, add params if needed
			if _, ok := ad.assets[aapp]; !ok {
				if val == nil {
					ad.assets[aapp] = nil
				} else {
					cp := *val
					ad.assets[aapp] = &cp
				}
			}
		}
	}
}

// Len returns number of stored accounts
func (ad *NewAccountDeltas) Len() int {
	return len(ad.accts)
}

// GetByIdx returns address and AccountData
// It does NOT check boundaries.
func (ad *NewAccountDeltas) GetByIdx(i int) (basics.Address, AccountData) {
	return ad.accts[i].Addr, ad.accts[i].AccountData
}

// Upsert updates or inserts the account data for a given address.
func (ad *NewAccountDeltas) Upsert(addr basics.Address, data AccountData) {
	if idx, exist := ad.acctsCache[addr]; exist { // nil map lookup is OK
		ad.accts[idx] = NewBalanceRecord{Addr: addr, AccountData: data}
		return
	}

	last := len(ad.accts)
	ad.accts = append(ad.accts, NewBalanceRecord{Addr: addr, AccountData: data})

	if ad.acctsCache == nil {
		ad.acctsCache = make(map[basics.Address]int)
	}
	ad.acctsCache[addr] = last
}

// UpsertAppParams updates or inserts the app params for a given address.
func (ad *NewAccountDeltas) UpsertAppParams(addr basics.Address, aidx basics.AppIndex, params *basics.AppParams) {
	ad.appParams[AccountApp{addr, aidx}] = params
}

// UpsertAssetParams updates or inserts the asset params for a given address.
func (ad *NewAccountDeltas) UpsertAssetParams(addr basics.Address, aidx basics.AssetIndex, params *basics.AssetParams) {
	ad.assetParams[AccountAsset{addr, aidx}] = params
}

// UpsertAppLocalState updates or inserts the app local state for a given address.
func (ad *NewAccountDeltas) UpsertAppLocalState(addr basics.Address, aidx basics.AppIndex, ls *basics.AppLocalState) {
	ad.appLocalStates[AccountApp{addr, aidx}] = ls
}

// UpsertAssetHolding updates or inserts the asset holding for a given address.
func (ad *NewAccountDeltas) UpsertAssetHolding(addr basics.Address, aidx basics.AssetIndex, holding *basics.AssetHolding) {
	ad.assets[AccountAsset{addr, aidx}] = holding
}

// func (ad *AccountDeltas) upsert(br basics.BalanceRecord) {
// 	addr := br.Addr
// 	if idx, exist := ad.acctsCache[addr]; exist { // nil map lookup is OK
// 		ad.accts[idx] = br
// 		return
// 	}

// 	last := len(ad.accts)
// 	ad.accts = append(ad.accts, br)

// 	if ad.acctsCache == nil {
// 		ad.acctsCache = make(map[basics.Address]int)
// 	}
// 	ad.acctsCache[addr] = last
// }

// OptimizeAllocatedMemory by reallocating maps to needed capacity
// For each data structure, reallocate if it would save us at least 50MB aggregate
func (sd *StateDelta) OptimizeAllocatedMemory(proto config.ConsensusParams) {
	/*
		// accts takes up 232 bytes per entry, and is saved for 320 rounds
		if uint64(cap(sd.Accts.accts)-len(sd.Accts.accts))*accountArrayEntrySize*proto.MaxBalLookback > stateDeltaTargetOptimizationThreshold {
			accts := make([]basics.BalanceRecord, len(sd.Accts.acctsCache))
			copy(accts, sd.Accts.accts)
			sd.Accts.accts = accts
		}

		// acctsCache takes up 64 bytes per entry, and is saved for 320 rounds
		// realloc if original allocation capacity greater than length of data, and space difference is significant
		if 2*sd.initialTransactionsCount > len(sd.Accts.acctsCache) &&
			uint64(2*sd.initialTransactionsCount-len(sd.Accts.acctsCache))*accountMapCacheEntrySize*proto.MaxBalLookback > stateDeltaTargetOptimizationThreshold {
			acctsCache := make(map[basics.Address]int, len(sd.Accts.acctsCache))
			for k, v := range sd.Accts.acctsCache {
				acctsCache[k] = v
			}
			sd.Accts.acctsCache = acctsCache
		}

		// TxLeases takes up 112 bytes per entry, and is saved for 1000 rounds
		if sd.initialTransactionsCount > len(sd.Txleases) &&
			uint64(sd.initialTransactionsCount-len(sd.Txleases))*txleasesEntrySize*proto.MaxTxnLife > stateDeltaTargetOptimizationThreshold {
			txLeases := make(map[Txlease]basics.Round, len(sd.Txleases))
			for k, v := range sd.Txleases {
				txLeases[k] = v
			}
			sd.Txleases = txLeases
		}

		// Creatables takes up 100 bytes per entry, and is saved for 320 rounds
		if uint64(len(sd.Creatables))*creatablesEntrySize*proto.MaxBalLookback > stateDeltaTargetOptimizationThreshold {
			creatableDeltas := make(map[basics.CreatableIndex]ModifiedCreatable, len(sd.Creatables))
			for k, v := range sd.Creatables {
				creatableDeltas[k] = v
			}
			sd.Creatables = creatableDeltas
		}
	*/
}

// GetBasicsAccountData returns the basics.AccountData for a given address.
func (ad NewAccountDeltas) GetBasicsAccountData(addr basics.Address) (basics.AccountData, bool) {
	result := basics.AccountData{}
	idx, ok := ad.acctsCache[addr]
	if !ok {
		return basics.AccountData{}, false
	}
	acct := ad.accts[idx].AccountData
	AssignAccountData(&result, acct)

	for aapp, val := range ad.appParams {
		if aapp.Address == addr {
			if val == nil {
				delete(result.AppParams, aapp.App)
			} else {
				result.AppParams[aapp.App] = *val
			}
		}
	}

	for aapp, val := range ad.appLocalStates {
		if aapp.Address == addr {
			if val == nil {
				delete(result.AppParams, aapp.App)
			} else {
				result.AppLocalStates[aapp.App] = *val
			}
		}
	}

	for aapp, val := range ad.assetParams {
		if aapp.Address == addr {
			if val == nil {
				delete(result.AssetParams, aapp.Asset)
			} else {
				result.AssetParams[aapp.Asset] = *val
			}
		}
	}

	for aapp, val := range ad.assets {
		if aapp.Address == addr {
			if val == nil {
				delete(result.Assets, aapp.Asset)
			} else {
				result.Assets[aapp.Asset] = *val
			}
		}
	}
	return result, true
}

// ToBasicsAccountDataMap converts these deltas into a map
func (ad NewAccountDeltas) ToBasicsAccountDataMap() map[basics.Address]basics.AccountData {
	result := make(map[basics.Address]basics.AccountData, ad.Len())
	for addr, idx := range ad.acctsCache {
		acct := ad.accts[idx].AccountData
		acctData := basics.AccountData{}
		AssignAccountData(&acctData, acct)
		result[addr] = acctData
	}

	for aapp, val := range ad.appParams {
		acctData, ok := result[aapp.Address]
		if !ok {
			panic(fmt.Sprintf("ToBasicAccountData: app params for (%s, %d) not in base deltas", aapp.Address.String(), aapp.App))
		}
		if val == nil {
			delete(acctData.AppParams, aapp.App)
		} else {
			if acctData.AppParams == nil {
				acctData.AppParams = make(map[basics.AppIndex]basics.AppParams)
			}
			acctData.AppParams[aapp.App] = *val
		}
		result[aapp.Address] = acctData
	}

	for aapp, val := range ad.appLocalStates {
		acctData, ok := result[aapp.Address]
		if !ok {
			panic(fmt.Sprintf("ToBasicAccountData: app states for (%s, %d) not in base deltas", aapp.Address.String(), aapp.App))
		}
		if val == nil {
			delete(acctData.AppLocalStates, aapp.App)
		} else {
			if acctData.AppLocalStates == nil {
				acctData.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
			}
			acctData.AppLocalStates[aapp.App] = *val
		}
		result[aapp.Address] = acctData
	}

	for aapp, val := range ad.assetParams {
		acctData, ok := result[aapp.Address]
		if !ok {
			panic(fmt.Sprintf("ToBasicAccountData: asset params for (%s, %d) not in base deltas", aapp.Address.String(), aapp.Asset))
		}
		if val == nil {
			delete(acctData.AssetParams, aapp.Asset)
		} else {
			if acctData.AssetParams == nil {
				acctData.AssetParams = make(map[basics.AssetIndex]basics.AssetParams)
			}
			acctData.AssetParams[aapp.Asset] = *val
		}
		result[aapp.Address] = acctData
	}

	for aapp, val := range ad.assets {
		acctData, ok := result[aapp.Address]
		if !ok {
			panic(fmt.Sprintf("ToBasicAccountData: asset holding for (%s, %d) not in base deltas", aapp.Address.String(), aapp.Asset))
		}
		if val == nil {
			delete(acctData.Assets, aapp.Asset)
		} else {
			if acctData.Assets == nil {
				acctData.Assets = make(map[basics.AssetIndex]basics.AssetHolding)
			}
			acctData.Assets[aapp.Asset] = *val
		}
		result[aapp.Address] = acctData
	}

	return result
}

// GetAllAppParams todo
func (ad *NewAccountDeltas) GetAllAppParams() map[AccountApp]*basics.AppParams {
	return ad.appParams
}

// GetAllAppLocalStates todo
func (ad *NewAccountDeltas) GetAllAppLocalStates() map[AccountApp]*basics.AppLocalState {
	return ad.appLocalStates
}

// GetAllAssetParams todo
func (ad *NewAccountDeltas) GetAllAssetParams() map[AccountAsset]*basics.AssetParams {
	return ad.assetParams
}

// GetAllAssets todo
func (ad *NewAccountDeltas) GetAllAssets() map[AccountAsset]*basics.AssetHolding {
	return ad.assets
}
