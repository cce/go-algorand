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

package internal

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/apply"
)

func (cs *roundCowState) TotalAppParams(creator basics.Address) (int, error) {
	acct, err := cs.lookup(creator)
	if err != nil {
		return 0, err
	}
	return len(acct.XAppParams), nil
}
func (cs *roundCowState) TotalAppLocalState(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return len(acct.XAppLocalStates), nil
}
func (cs *roundCowState) TotalAssetHolding(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return len(acct.XAssets), nil
}
func (cs *roundCowState) TotalAssetParams(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return len(acct.XAssetParams), nil
}

func (cs *roundCowState) GetAppParams(creator basics.Address, aidx basics.AppIndex) (params basics.AppParams, err error) {
	acct, err := cs.lookup(creator)
	if err != nil {
		return
	}
	params, ok := acct.XAppParams[aidx]
	if !ok {
		err = apply.ErrCreatableNotFound
		return
	}
	return
}
func (cs *roundCowState) GetAppLocalState(addr basics.Address, aidx basics.AppIndex) (state basics.AppLocalState, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	state, ok := acct.XAppLocalStates[aidx]
	if !ok {
		err = apply.ErrCreatableNotFound
		return
	}
	return
}
func (cs *roundCowState) GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (holding basics.AssetHolding, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	holding, ok := acct.XAssets[aidx]
	if !ok {
		err = apply.ErrCreatableNotFound
		return
	}
	return
}
func (cs *roundCowState) GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (params basics.AssetParams, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	params, ok := acct.XAssetParams[aidx]
	if !ok {
		err = apply.ErrCreatableNotFound
		return
	}
	return
}

func (cs *roundCowState) PutAppParams(addr basics.Address, aidx basics.AppIndex, params basics.AppParams) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	ap := make(map[basics.AppIndex]basics.AppParams, len(acct.XAppParams))
	for k, v := range acct.XAppParams {
		ap[k] = v
	}
	ap[aidx] = params
	acct.XAppParams = ap
	return cs.Put(addr, acct)
}
func (cs *roundCowState) PutAppLocalState(addr basics.Address, aidx basics.AppIndex, state basics.AppLocalState) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	als := make(map[basics.AppIndex]basics.AppLocalState, len(acct.XAppLocalStates))
	for k, v := range acct.XAppLocalStates {
		als[k] = v
	}
	als[aidx] = state
	acct.XAppLocalStates = als
	return cs.Put(addr, acct)
}
func (cs *roundCowState) PutAssetHolding(addr basics.Address, aidx basics.AssetIndex, data basics.AssetHolding) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	ah := make(map[basics.AssetIndex]basics.AssetHolding, len(acct.XAssets))
	for k, v := range acct.XAssets {
		ah[k] = v
	}
	ah[aidx] = data
	acct.XAssets = ah
	return cs.Put(addr, acct)
}
func (cs *roundCowState) PutAssetParams(addr basics.Address, aidx basics.AssetIndex, data basics.AssetParams) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	ap := make(map[basics.AssetIndex]basics.AssetParams, len(acct.XAssetParams))
	for k, v := range acct.XAssetParams {
		ap[k] = v
	}
	ap[aidx] = data
	acct.XAssetParams = ap
	return cs.Put(addr, acct)
}

func (cs *roundCowState) DeleteAppParams(addr basics.Address, aidx basics.AppIndex) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	delete(acct.XAppParams, aidx)
	return cs.Put(addr, acct)
}
func (cs *roundCowState) DeleteAppLocalState(addr basics.Address, aidx basics.AppIndex) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	delete(acct.XAppLocalStates, aidx)
	return cs.Put(addr, acct)
}
func (cs *roundCowState) DeleteAssetHolding(addr basics.Address, aidx basics.AssetIndex) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	delete(acct.XAssets, aidx)
	return cs.Put(addr, acct)
}
func (cs *roundCowState) DeleteAssetParams(addr basics.Address, aidx basics.AssetIndex) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	delete(acct.XAssetParams, aidx)
	return cs.Put(addr, acct)
}

func (cs *roundCowState) CheckAppLocalState(addr basics.Address, aidx basics.AppIndex) (ok bool, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	_, ok = acct.XAppLocalStates[aidx]
	return
}

func (cs *roundCowState) CheckAssetParams(addr basics.Address, aidx basics.AssetIndex) (ok bool, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	_, ok = acct.XAssetParams[aidx]
	return
}
