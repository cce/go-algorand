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

package internal

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
)

// These functions ensure roundCowState satisfies the methods for
// accessing asset and app data in the apply.Balances interface.

func (cs *roundCowState) CountAppParams(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return int(acct.TotalAppParams), nil
}

func (cs *roundCowState) CountAppLocalState(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return int(acct.TotalAppLocalStates), nil
}

func (cs *roundCowState) CountAssetHolding(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return int(acct.TotalAssets), nil
}

func (cs *roundCowState) CountAssetParams(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return int(acct.TotalAssetParams), nil
}

func (cs *roundCowState) GetAppParams(addr basics.Address, aidx basics.AppIndex) (ret basics.AppParams, ok bool, err error) {
	return cs.lookupAppParams(addr, aidx)
}

func (cs *roundCowState) GetAppLocalState(addr basics.Address, aidx basics.AppIndex) (ret basics.AppLocalState, ok bool, err error) {
	return cs.lookupAppLocalState(addr, aidx)
}

func (cs *roundCowState) GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (ret basics.AssetHolding, ok bool, err error) {
	return cs.lookupAssetHolding(addr, aidx)
}

func (cs *roundCowState) GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (ret basics.AssetParams, ok bool, err error) {
	return cs.lookupAssetParams(addr, aidx)
}

func (cs *roundCowState) PutAppParams(addr basics.Address, aidx basics.AppIndex, params basics.AppParams) error {
	return cs.putAppParams(addr, aidx, &params)
}

func (cs *roundCowState) putAppParams(addr basics.Address, aidx basics.AppIndex, params *basics.AppParams) error {
	var state *basics.AppLocalState
	if as, ok, err := cs.lookupAppLocalState(addr, aidx); err != nil { // should be cached
		return err
	} else if ok {
		state = &as
	}
	cs.mods.NewAccts.UpsertAppParams(addr, aidx, params)
	cs.mods.NewAccts.UpsertAppLocalState(addr, aidx, state)
	return nil
}

func (cs *roundCowState) PutAppLocalState(addr basics.Address, aidx basics.AppIndex, state basics.AppLocalState) error {
	return cs.putAppLocalState(addr, aidx, &state)
}

func (cs *roundCowState) putAppLocalState(addr basics.Address, aidx basics.AppIndex, state *basics.AppLocalState) error {
	var params *basics.AppParams
	if ap, ok, err := cs.lookupAppParams(addr, aidx); err != nil { // should be cached
		return err
	} else if ok {
		params = &ap
	}
	cs.mods.NewAccts.UpsertAppParams(addr, aidx, params)
	cs.mods.NewAccts.UpsertAppLocalState(addr, aidx, state)
	return nil
}

func (cs *roundCowState) PutAssetHolding(addr basics.Address, aidx basics.AssetIndex, data basics.AssetHolding) error {
	return cs.putAssetHolding(addr, aidx, &data)
}

func (cs *roundCowState) putAssetHolding(addr basics.Address, aidx basics.AssetIndex, data *basics.AssetHolding) error {
	var params *basics.AssetParams
	if ap, ok, err := cs.lookupAssetParams(addr, aidx); err != nil { // should be cached
		return err
	} else if ok {
		params = &ap
	}
	cs.mods.NewAccts.UpsertAssetHolding(addr, aidx, data)
	cs.mods.NewAccts.UpsertAssetParams(addr, aidx, params)
	return nil
}

func (cs *roundCowState) PutAssetParams(addr basics.Address, aidx basics.AssetIndex, data basics.AssetParams) error {
	return cs.putAssetParams(addr, aidx, &data)
}

func (cs *roundCowState) putAssetParams(addr basics.Address, aidx basics.AssetIndex, data *basics.AssetParams) error {
	var holding *basics.AssetHolding
	if ah, ok, err := cs.lookupAssetHolding(addr, aidx); err != nil { // should be cached
		return err
	} else if ok {
		holding = &ah
	}
	cs.mods.NewAccts.UpsertAssetHolding(addr, aidx, holding)
	cs.mods.NewAccts.UpsertAssetParams(addr, aidx, data)
	return nil
}

func (cs *roundCowState) DeleteAppParams(addr basics.Address, aidx basics.AppIndex) error {
	if _, ok := cs.mods.NewAccts.GetData(addr); !ok {
		return fmt.Errorf("DeleteAppParams: %s not found in deltas for %d", addr.String(), aidx)
	}

	return cs.putAppParams(addr, aidx, nil)
}

func (cs *roundCowState) DeleteAppLocalState(addr basics.Address, aidx basics.AppIndex) error {
	if _, ok := cs.mods.NewAccts.GetData(addr); !ok {
		return fmt.Errorf("DeleteAppLocalState: %s not found in deltas for %d", addr.String(), aidx)
	}

	return cs.putAppLocalState(addr, aidx, nil)
}

func (cs *roundCowState) DeleteAssetHolding(addr basics.Address, aidx basics.AssetIndex) error {
	if _, ok := cs.mods.NewAccts.GetData(addr); !ok {
		return fmt.Errorf("DeleteAssetHolding: %s not found in deltas for %d", addr.String(), aidx)
	}

	return cs.putAssetHolding(addr, aidx, nil)
}

func (cs *roundCowState) DeleteAssetParams(addr basics.Address, aidx basics.AssetIndex) error {
	if _, ok := cs.mods.NewAccts.GetData(addr); !ok {
		return fmt.Errorf("DeleteAssetParams: %s not found in deltas for %d", addr.String(), aidx)
	}

	return cs.putAssetParams(addr, aidx, nil)
}

func (cs *roundCowState) HasAppLocalState(addr basics.Address, aidx basics.AppIndex) (ok bool, err error) {
	_, ok, err = cs.lookupAppLocalState(addr, aidx)
	return
}

func (cs *roundCowState) HasAssetParams(addr basics.Address, aidx basics.AssetIndex) (ok bool, err error) {
	_, ok, err = cs.lookupAssetParams(addr, aidx)
	return
}
