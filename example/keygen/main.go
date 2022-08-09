// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
	s256k1 "github.com/btcsuite/btcd/btcec"
)

const threshold = 3
const partyCount = 5

func main() {
	// tss.SetCurve(s256k1.S256())
	time0 := time.Now()
	var parties tss.UnSortedPartyIDs
	var outs []chan tss.Message
	var ins []chan tss.Message
	var saves []chan keygen.LocalPartySaveData

	var localDatas [partyCount]keygen.LocalPartySaveData

	for i := 0; i < partyCount; i++ {
		party := genNewParty(i)
		parties = append(parties, party)
		outs = append(outs, make(chan tss.Message))
		ins = append(ins, make(chan tss.Message))
		saves = append(saves, make(chan keygen.LocalPartySaveData))
	}

	// 生成密钥
	wg := sync.WaitGroup{}
	for i := 0; i < partyCount; i++ {
		index := i
		in := ins[index]
		out := outs[index]
		save := saves[index]
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := genKey(parties, index, out, in, save)
			if err != nil {
				panic(err)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for msg := range out {
				for j := 0; j < partyCount; j++ {
					if j != index {
						ins[j] <- msg
					}
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(in)
			for data := range save {
				localDatas[index] = data
			}
		}()
	}

	wg.Wait()

	time1 := time.Now()
	fmt.Println(time1.Sub(time0))

	fmt.Println(len(localDatas))

	// 生成签名
	var signOuts []chan tss.Message
	var signIns []chan tss.Message
	for i := 0; i < threshold+1; i++ {
		signOuts = append(signOuts, make(chan tss.Message))
		signIns = append(signIns, make(chan tss.Message))
	}

	wg = sync.WaitGroup{}
	for i := 0; i < threshold+1; i++ {
		index := i
		in := signIns[index]
		out := signOuts[index]
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(in)
			err := sign(parties[:threshold+1], index, localDatas[index], out, in)
			if err != nil {
				panic(err)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for msg := range out {
				for j := 0; j < threshold+1; j++ {
					if j != index {
						signIns[j] <- msg
					}
				}
			}
		}()
	}

	wg.Wait()

}

func sign(unSortedIds tss.UnSortedPartyIDs, i int, saveData keygen.LocalPartySaveData, out chan<- tss.Message, in <-chan tss.Message) error {
	defer close(out)

	fmt.Println(i, "signing start")
	sortParties := tss.SortPartyIDs(unSortedIds)
	p2pCtx := tss.NewPeerContext(sortParties)

	parties := make([]*signing.LocalParty, 0, len(sortParties))
	params := tss.NewParameters(s256k1.S256(), p2pCtx, unSortedIds[i], len(parties), threshold)

	errCh := make(chan *tss.Error)
	outCh := make(chan tss.Message)
	endCh := make(chan common.SignatureData)

	defer close(outCh)
	defer close(endCh)
	defer close(errCh)

	party := signing.NewLocalParty(big.NewInt(42), params, saveData, outCh, endCh).(*signing.LocalParty)
	go func() {
		fmt.Println(i, party.PartyID().Index, "start")
		if err := party.Start(); err != nil {
			fmt.Println(party.PartyID().Index, "send err = ", err.Error())
			errCh <- err
		}
	}()

	for {
		select {
		case err := <-errCh:
			fmt.Println(party.PartyID().Index, "get err = ", err.Error())
			return errors.New(err.Error())
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // 广播给所有用户的
				fmt.Println(party.PartyID().Index, "broadcast msg", msg.String())
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					fmt.Println(party.PartyID().Index, "send continue ")
					continue
				}
				fmt.Println(party.PartyID().Index, "send to", dest[0].Index, "msg", msg.String())
			}
			out <- msg
		case result := <-endCh:
			fmt.Println(party.PartyID().Index, "end sign.")
			fmt.Println(hex.EncodeToString(result.Signature))
			return nil
		case msg := <-in:
			fmt.Println(party.PartyID().Index, "update from", msg.GetFrom().Index, "msg type", msg.Type())
			dest := msg.GetTo()
			if dest == nil {
				if party.PartyID().Index == msg.GetFrom().Index {
					fmt.Println(party.PartyID().Index, "broadcast in continue ")
					continue
				}
			} else {
				if dest[0].Index != party.PartyID().Index {
					fmt.Println(party.PartyID().Index, "in continue ")
					continue
				}
			}

			go test.SharedPartyUpdater(party, msg, errCh)
		}
	}
}

func genKey(unSortedIds tss.UnSortedPartyIDs, i int, out chan<- tss.Message, in <-chan tss.Message, end chan<- keygen.LocalPartySaveData) error {
	defer close(out)
	defer close(end)

	fmt.Println(i, "genKey start")

	preParams, _ := keygen.GeneratePreParams(1 * time.Minute)

	sortParties := tss.SortPartyIDs(unSortedIds)
	ctx := tss.NewPeerContext(sortParties)

	params := tss.NewParameters(s256k1.S256(), ctx, unSortedIds[i], partyCount, threshold)

	errCh := make(chan *tss.Error)
	outCh := make(chan tss.Message)
	endCh := make(chan keygen.LocalPartySaveData)

	defer close(outCh)
	defer close(endCh)
	defer close(errCh)

	party := keygen.NewLocalParty(params, outCh, endCh, *preParams)

	go func() {
		fmt.Println(i, party.PartyID().Index, "start")
		if err := party.Start(); err != nil {
			fmt.Println(party.PartyID().Index, "send err = ", err.Error())
			errCh <- err
		}
	}()

	for {
		select {
		case err := <-errCh:
			fmt.Println(party.PartyID().Index, "get err = ", err.Error())
			return errors.New(err.Error())
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // 广播给所有用户的
				fmt.Println(party.PartyID().Index, "broadcast msg", msg.String())
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					fmt.Println(party.PartyID().Index, "send continue ")
					continue
				}
				fmt.Println(party.PartyID().Index, "send to", dest[0].Index, "msg", msg.String())
			}
			out <- msg
		case save := <-endCh:
			fmt.Println(party.PartyID().Index, "end key gen.")
			end <- save
			return nil
		case msg := <-in:
			dest := msg.GetTo()
			if dest == nil {
				if party.PartyID().Index == msg.GetFrom().Index {
					fmt.Println(party.PartyID().Index, "broadcast in continue ")
					continue
				}
			} else {
				if dest[0].Index != party.PartyID().Index {
					fmt.Println(party.PartyID().Index, "in continue ")
					continue
				}
			}
			fmt.Println(party.PartyID().Index, "update from", msg.GetFrom().Index, "msg type", msg.Type())
			go test.SharedPartyUpdater(party, msg, errCh)
		}
	}
}

func genNewParty(i int) *tss.PartyID {
	id := fmt.Sprintf("id%d", i)

	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		panic(err)
	}

	bigKey := big.NewInt(0).SetBytes(key[:])
	bigKey = bigKey.Mod(bigKey, s256k1.S256().N)

	thisParty := tss.NewPartyID(id, id, bigKey)
	return thisParty
}
