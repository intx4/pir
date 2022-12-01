package test

import (
	"bytes"
	"fmt"
	"math/rand"
	"pir"
	"pir/settings"
	"pir/utils"
	"testing"
)

var DEBUG = true

func TestClientQueryGen(t *testing.T) {
	items := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16}
	sizes := []int{150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			for _, dimentions := range []int{2, 3} {
				context, err := settings.NewPirContext(item, size, dimentions, 14, 65537, 16)
				if err != nil {
					t.Fatalf(err.Error())
				}
				box, err := settings.NewHeBox(context)
				if err != nil {
					t.Fatalf(err.Error())
				}
				client := pir.NewPirClient(*context, *box)

				keys := make([][]byte, item)
				values := make([][]byte, item)
				for i := range keys {
					keys[i] = RandByteString(100)
					values[i] = RandByteString(size)
				}
				choice := rand.Int() % len(keys)
				_, choosenIdx := utils.MapKeyToIdx(keys[choice], context.Kd, context.Dimentions)
				query, err := client.QueryGen(keys[choice])
				if err != nil {
					t.Fatalf(err.Error())
				}
				for d, di := range choosenIdx {
					q := query[d]
					for i, ct := range q {
						pt := client.Box.Dec.DecryptNew(ct)
						v := client.Box.Ecd.DecodeUintNew(pt)
						if i == di {
							for _, n := range v {
								if n != uint64(1) {
									t.Fatalf("Expected 1 got %d at index %d", n, di)
								}
							}
						} else {
							for _, n := range v {
								if n != uint64(0) {
									t.Fatalf("Expected 0 got %d at index %d", n, di)
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestClientRetrieval(t *testing.T) {
	//DB dimentions
	items := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16}
	sizes := []int{150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			for _, dimentions := range []int{2, 3} {
				//first we create a context for the PIR
				context, err := settings.NewPirContext(item, size, dimentions, 14, 65537, 14)
				if err != nil {
					t.Fatalf(err.Error())
				}
				//we feed the context to a new HE box, wrapping all the crypto tools needed
				box, err := settings.NewHeBox(context)
				if err != nil {
					t.Fatalf(err.Error())
				}
				//we create a client with the new box and context, and a relinearization key to be given to the server
				client := pir.NewPirClient(*context, *box)
				rlk, err := client.GenRelinKey()
				if err != nil {
					t.Fatalf(err.Error())
				}
				keys := make([][]byte, item)
				values := make([][]byte, item)

				//generate a random db
				for i := range keys {
					keys[i] = RandByteString(100)
					values[i] = RandByteString(size / 8)
				}
				//we create a new server
				server, err := pir.NewPirServer(*context, *box, keys, values)

				if err != nil {
					t.Fatalf(err.Error())
				}
				//pick a key, and create its label. With that, create the query
				choice := rand.Int() % len(keys)
				choosenKey, _ := utils.MapKeyToIdx(keys[choice], context.Kd, context.Dimentions)
				query, err := client.QueryGen(keys[choice])
				if err != nil {
					t.Fatalf(err.Error())
				}
				//server encodes its storage into plaintexts
				ecdStorage, err := server.Encode()
				if err != nil {
					t.Fatalf(err.Error())
				}
				//server creates the answer. Note we need to pass the relin key as well
				if DEBUG {
					server.Box.Dec = client.Box.Dec
				}
				answerEnc, err := server.AnswerGen(ecdStorage, query, rlk)
				if err != nil {
					t.Fatalf(err.Error())
				}
				//extract the answer
				answerPt, err := client.AnswerGet(answerEnc)
				if err != nil {
					t.Fatalf(err.Error())
				}
				if bytes.Compare(server.Store[choosenKey].Coalesce(), answerPt) != 0 {
					fmt.Println("Want")
					fmt.Println(server.Store[choosenKey].Value)
					fmt.Println("Got")
					fmt.Println(answerPt)
					t.Fatalf("Answer does not match expected")
				}
			}
		}
	}
}
