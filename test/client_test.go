package test

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"log"
	"math/rand"
	"os"
	"pir"
	"pir/settings"
	"pir/utils"
	"strings"
	"testing"
	"time"
)

var DEBUG = false

func TestClientQueryGen(t *testing.T) {
	items := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16}
	sizes := []int{150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			for _, dimentions := range []int{2, 3} {
				context, err := settings.NewPirContext(item, size, dimentions, 13, 65537, 16)
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
	listOfEntries := []int{1 << 16, 1 << 18, 1 << 20}
	sizes := []int{150 * 8, 250 * 8}

	os.Remove("data/pirGo.csv")
	csvFile, err := os.Create("data/pirGo.csv")
	if err != nil {
		t.Fatalf(err.Error())
	}
	csvW := csv.NewWriter(csvFile)

	defer csvFile.Close()

	headers := []string{"entries", "size", "d", "ecd_time", "ecd_size", "query_gen_time", "answer_gen_time", "answer_get_time", "tot_time", "query_size", "answer_size"}
	csvW.Write(headers)

	for _, entries := range listOfEntries {
		for _, size := range sizes {
			for _, dimentions := range []int{2, 3} {
				//first we create a context for the PIR
				context, err := settings.NewPirContext(entries, size, dimentions, 13, 65537, 16)
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
				keys := make([][]byte, entries)
				values := make([][]byte, entries)

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

				start := time.Now()
				query, err := client.QueryGen(keys[choice])
				queryGenTime := time.Since(start).Seconds()

				if err != nil {
					t.Fatalf(err.Error())
				}
				//server encodes its storage into plaintexts
				start = time.Now()
				ecdStorage, err := server.Encode()
				ecdTime := time.Since(start).Seconds()
				ecdSize := 0
				ecdStorageAsMap := make(map[string][]*bfv.PlaintextMul)
				ecdStorage.Range(func(key, value any) bool {
					valueToStore := make([]*bfv.PlaintextMul, len(value.([]rlwe.Operand)))
					for i, v := range value.([]rlwe.Operand) {
						valueToStore[i] = v.(*bfv.PlaintextMul)
					}
					ecdStorageAsMap[key.(string)] = valueToStore
					return true
				})
				for _, e := range ecdStorageAsMap {
					for _, pt := range e {
						serialized, err := pt.MarshalBinary()
						ecdSize += len(serialized)
						if err != nil {
							t.Fatalf(err.Error())
						}
					}
				}

				if err != nil {
					t.Fatalf(err.Error())
				}
				//server creates the answer. Note we need to pass the relin key as well
				if DEBUG {
					server.Box.Dec = client.Box.Dec
				}
				start = time.Now()
				answerEnc, err := server.AnswerGen(ecdStorage, query, rlk)
				answerGenTime := time.Since(start).Seconds()

				if err != nil {
					t.Fatalf(err.Error())
				}
				//extract the answer
				start = time.Now()
				answerPt, err := client.AnswerGet(answerEnc)
				answerGetTime := time.Since(start).Seconds()

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
				querySize := 0
				for _, q := range query {
					serialized, err := q[0].MarshalBinary()
					querySize += len(serialized) * len(q)
					if err != nil {
						t.Fatalf(err.Error())
					}
				}
				answerSize := 0
				for _, a := range answerEnc {
					serialized, err := a.MarshalBinary()
					answerSize += len(serialized)
					if err != nil {
						t.Fatalf(err.Error())
					}
				}

				records := fmt.Sprintf("%d, %d, %d, %f, %d, %f, %f, %f, %f, %d, %d", entries, size/8, dimentions, ecdTime, ecdSize, queryGenTime, answerGenTime, answerGetTime, ecdTime+queryGenTime+answerGenTime+answerGetTime, querySize, answerSize)
				err = csvW.Write(strings.Split(records, ","))
				if err != nil {
					t.Logf(err.Error())
				}
				csvW.Flush()
				err = csvW.Error()
				if err != nil {
					t.Logf(err.Error())
				}
				records = fmt.Sprintf("Entries : %d, Size : %d, Dimentions : %d, Ecd Time : %f, Ecd Size : %d, Query Gen Time : %f, Answer Gen Time : %f, Answer Get Time : %f, Tot Time : %f, Query Size : %d, Answer Size : %d", entries, size/8, dimentions, ecdTime, ecdSize, queryGenTime, answerGenTime, answerGetTime, ecdTime+queryGenTime+answerGenTime+answerGetTime, querySize, answerSize)
				log.Println(records)
			}
		}
	}
}
