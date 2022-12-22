package test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"log"
	"math"
	"math/rand"
	"os"
	"pir"
	"pir/settings"
	"pir/utils"
	"runtime"
	"strings"
	"testing"
	"time"
)

var DEBUG = true
var DIR = os.ExpandEnv("$HOME/pir/test/data/")
var ListOfEntries = []int{1 << 14, 1 << 16, 1 << 18, 1 << 20}
var Sizes = []int{30 * 8, 188 * 8, 288 * 8}

func testClientRetrieval(t *testing.T, path string, expansion bool, weaklyPrivate bool, leakage int) {
	csvFile := new(os.File)
	var err error
	if !weaklyPrivate || (weaklyPrivate && leakage == 1) {
		os.Remove(path)
		csvFile, err = os.Create(path)
		if err != nil {
			t.Fatalf(err.Error())
		}
	} else if weaklyPrivate && leakage == 2 {
		csvFile, err = os.OpenFile(path, os.O_APPEND, 0644)
		if err != nil {
			t.Fatalf(err.Error())
		}
	}
	csvW := csv.NewWriter(csvFile)

	defer csvFile.Close()

	headers := []string{"entries", "size", "d", "n", "ecd_time", "ecd_size", "query_gen_time", "answer_gen_time", "answer_get_time", "tot_time", "query_size", "answer_size", "leakedBits", "informationBits"}
	csvW.Write(headers)

	for _, entries := range ListOfEntries {
		for _, size := range Sizes {
			//fake db
			keys := make([]string, entries)
			values := make([][]byte, entries)
			db := make(map[string][]byte)
			for i := 0; i < len(keys); {
				keys[i] = string(RandByteString(100))
				values[i] = RandByteString(size / 8)
				if _, ok := db[keys[i]]; !ok {
					db[keys[i]] = values[i]
					i++
				}
			}
			for _, dimentions := range []int{2} {
				for _, logN := range []int{13, 14} {
					//first we create some parameters
					params := settings.GetsParamForPIR(logN, dimentions, expansion, weaklyPrivate, leakage)
					//now we create a new client instance
					client := pir.NewPirClient([]bfv.Parameters{params}, "1")
					//now we create a profile which contains all the params and keys needed to server
					profile := client.GenProfile()

					server := pir.NewPirServer()
					server.AddProfile(profile)
					serverBox, err := server.WithParams(profile.ClientId, profile.CryptoParams[0].ParamsId)
					if err != nil {
						t.Fatalf(err.Error())
					}
					//now the server is able to create a context with the params provided by client
					ctx, err := settings.NewPirContext(entries, size, serverBox.Params, profile.CryptoParams[0].ParamsId)
					if err != nil {
						t.Fatalf(err.Error())
					}
					choice := rand.Int() % len(keys)
					start := time.Now()
					query, leakedBits, err := client.QueryGen([]byte(keys[choice]), ctx, dimentions, pir.NONE, weaklyPrivate, expansion)
					queryGenTime := time.Since(start).Seconds()
					clientBox := client.SetsOfBox[utils.FormatParams(params)]
					choosenKey, _ := utils.MapKeyToDim([]byte(keys[choice]), query.Kd, query.Dimentions)
					if err != nil {
						t.Fatalf(err.Error())
					}
					//server encodes its storage into plaintexts
					start = time.Now()
					queryProc, err := server.ProcessPIRQuery(query, serverBox)
					if err != nil {
						t.Fatalf(err.Error())
					}
					ecdStorage, err := server.Encode(query.K, query.Kd, query.Dimentions, ctx, serverBox, queryProc, db)
					if err != nil {
						t.Fatalf(err.Error())
					}
					ecdTime := time.Since(start).Seconds()
					ecdSize := 0
					ecdStorageAsMap := make(map[string]*pir.PIREntry)
					ecdStorage.Range(func(key, value any) bool {
						ecdStorageAsMap[key.(string)] = value.(*pir.PIREntry)
						return true
					})
					for _, e := range ecdStorageAsMap {
						serialized, err := json.Marshal(e)
						ecdSize += len(serialized)
						if err != nil {
							t.Fatalf(err.Error())
						}
					}

					if err != nil {
						t.Fatalf(err.Error())
					}
					//server creates the answer. Note we need to pass the relin key as well
					if DEBUG {
						serverBox.Dec = clientBox.Dec
					}
					if err != nil {
						t.Fatalf(err.Error())
					}
					start = time.Now()
					answerEnc, err := server.AnswerGen(ecdStorage, serverBox, queryProc, query.K, query.Kd, query.Dimentions)
					answerGenTime := time.Since(start).Seconds()

					if err != nil {
						t.Fatalf(err.Error())
					}
					//extract the answer
					start = time.Now()
					answerPt, err := client.AnswerGet(answerEnc, clientBox)
					answerGetTime := time.Since(start).Seconds()

					if err != nil {
						t.Fatalf(err.Error())
					}
					expected, _ := server.Store.Load(choosenKey)
					if bytes.Compare(expected.(*pir.PIREntry).Coalesce(), answerPt) != 0 {
						fmt.Println("Want")
						fmt.Println(expected.(*pir.PIREntry).Value)
						fmt.Println("Got")
						fmt.Println(answerPt)
						t.Fatalf("Answer does not match expected")
					}
					qs, err := json.Marshal(query)
					if err != nil {
						t.Fatalf(err.Error())
					}
					querySize := len(qs)
					answerSize := 0
					for _, a := range answerEnc {
						serialized, err := a.MarshalBinary()
						answerSize += len(serialized)
						if err != nil {
							t.Fatalf(err.Error())
						}
					}

					records := fmt.Sprintf("%d, %d, %d, %d, %f, %d, %f, %f, %f, %f, %d, %d,%f, %f", entries, size/8, dimentions, logN, ecdTime, ecdSize, queryGenTime, answerGenTime, answerGetTime, ecdTime+queryGenTime+answerGenTime+answerGetTime, querySize, answerSize, leakedBits, math.Log2(float64(ctx.DBItems)))
					err = csvW.Write(strings.Split(records, ","))
					if err != nil {
						t.Logf(err.Error())
					}
					csvW.Flush()
					err = csvW.Error()
					if err != nil {
						t.Logf(err.Error())
					}
					records = fmt.Sprintf("Entries : %d, Size : %d, Dimentions : %d, N: %d, Ecd Time : %f, Ecd Size : %d, Query Gen Time : %f, Answer Gen Time : %f, Answer Get Time : %f, Tot Time : %f, Query Size : %d, Answer Size : %d, Leaked Bits : %f / %f", entries, size/8, dimentions, logN, ecdTime, ecdSize, queryGenTime, answerGenTime, answerGetTime, ecdTime+queryGenTime+answerGenTime+answerGetTime, querySize, answerSize, leakedBits, math.Log2(float64(ctx.DBItems)))
					log.Println(records)
				}
			}
		}
	}
}

func TestClientRetrieval(t *testing.T) {
	//DB dimentions
	os.Chdir(DIR)
	log.Println("Starting test. NumThreads = ", runtime.NumCPU())
	testCases := []struct {
		name          string
		path          string
		expansion     bool
		weaklyPrivate bool
		leakage       int
	}{
		{"No Expansion", "pirGo.csv", false, false, 0},
		{"Expansion", "pirGoExp.csv", true, false, 0},
		{"WPIR STD", "pirGoWP.csv", true, true, 1},
		{"WPIR STD", "pirGoWP.csv", true, true, 2},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testClientRetrieval(t, tc.path, tc.expansion, tc.weaklyPrivate, tc.leakage)
		})
	}
}
