package test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	Client "pir/client"
	"pir/messages"
	Server "pir/server"
	"pir/settings"
	"pir/utils"
	"runtime"
	"strings"
	"testing"
	"time"
)

var DEBUG = true
var DIR = os.ExpandEnv("$HOME/pir/test/data/")
var ListOfEntries = []int{1 << 16, 1 << 27, 1 << 26, 1 << 24, 1 << 20}
var Sizes = []int{288 * 8, 30 * 8}

func testClientRetrieval(t *testing.T, path string, expansion bool, weaklyPrivate bool, leakage int) {
	csvFile := new(os.File)
	var err error
	skipHeader := false
	if !weaklyPrivate || (weaklyPrivate && leakage == messages.STANDARDLEAKAGE) {
		os.Remove(path)
		csvFile, err = os.Create(path)
		if err != nil {
			t.Fatalf(err.Error())
		}
	} else if weaklyPrivate && leakage == messages.HIGHLEAKAGE {
		csvFile, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			t.Fatalf(err.Error())
		}
		skipHeader = true
	}
	csvW := csv.NewWriter(csvFile)

	defer csvFile.Close()

	headers := []string{"entries", "size", "max_entries", "d", "n", "ecd_time", "ecd_size", "query_gen_time", "query_size", "answer_gen_time", "answer_size", "answer_get_time", "tot_time", "online_time", "leakedBits", "informationBits"}
	if !skipHeader {
		csvW.Write(headers)
	}
	/*
		HC := new(settings.HyperCube)
		file, err := os.ReadFile(DIR + "hypercube.json")
		if err != nil {
			t.Fatalf(err.Error())
		}
		err = json.Unmarshal(file, HC)
		if err != nil {
			t.Fatalf(err.Error())
		}
	*/
	for _, entries := range ListOfEntries {
		if entries > 1<<26 && !weaklyPrivate {
			continue
		}
		maxEntries := entries
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
			for _, dimentions := range []int{3} {
				if !weaklyPrivate {
					if dimentions > 3 {
						continue
					}
				}
				for _, logN := range []int{14} {
					if !weaklyPrivate {
						if logN == 12 {
							continue
						}
					}
					log.Println(fmt.Sprintf("Testing %d entries, logN %d", entries, logN))
					//first we create some parameters
					paramsId, params := settings.GetsParamForPIR(logN, dimentions, expansion, weaklyPrivate, leakage)
					ctx, err := settings.NewPirContext(maxEntries, size, params.N(), dimentions)
					if err != nil {
						t.Logf(err.Error())
						continue
					}
					//create a server
					server := Server.NewPirServerBenchmark()
					//now we create a new pir instance
					client := Client.NewPirClient("1", "", nil, nil)
					//now we create a profile which contains all the params and keys needed to server
					client.AddContext(ctx)
					profile, err := client.GenProfile(params, paramsId)
					if err != nil {
						t.Fatalf(err.Error())
					}

					choice := rand.Int() % len(keys)
					start := time.Now()
					query, leakedBits, err := client.QueryGen([]byte(keys[choice]), profile, leakage, weaklyPrivate, expansion, true)
					if err != nil {
						t.Fatalf(err.Error())
					}
					queryGenTime := time.Since(start).Seconds()
					choosenKey, _ := utils.MapKeyToDim([]byte(keys[choice]), ctx.Kd, ctx.Dim)
					if err != nil {
						t.Fatalf(err.Error())
					}
					//add profile, create he box
					if query.Profile != nil {
						server.AddProfile(query.ClientId, query.Profile)
					}
					serverBox, err := server.WithParams(params, query.ClientId)
					if err != nil {
						t.Fatalf(err.Error())
					}
					if DEBUG {
						serverBox.Dec = profile.Box.Dec
					}
					//server encodes its storage into hypercube
					start = time.Now()
					ecdStorage, err := server.EncodeBenchmark(ctx, db)
					expected, _ := ecdStorage.Load(choosenKey)
					if err != nil {
						t.Fatalf(err.Error())
					}
					ecdTime := time.Since(start).Seconds()
					ecdSize := 0
					ecdStorage.Range(func(key, value any) bool {
						serialized, err := json.Marshal(value.(*Server.PIREntryBenchmark))
						ecdSize += len(serialized)
						if err != nil {
							t.Fatalf(err.Error())
						}
						return true
					})

					if err != nil {
						t.Fatalf(err.Error())
					}
					start = time.Now()
					queryProc, err := server.ProcessPIRQuery(ctx, query, serverBox)
					if err != nil {
						t.Fatalf(err.Error())
					}
					answerEnc, err := server.AnswerGenBenchmark(ecdStorage, serverBox, query.Prefix, queryProc, ctx)
					answerGenTime := time.Since(start).Seconds()

					if err != nil {
						t.Fatalf(err.Error())
					}
					//extract the answer
					start = time.Now()
					answerPt, err := client.AnswerGet(profile, answerEnc)
					answerGetTime := time.Since(start).Seconds()

					if err != nil {
						t.Logf(err.Error())
						s, _ := settings.GetsParamForPIR(logN, dimentions, expansion, weaklyPrivate, leakage)
						t.Logf("Broken set of params: " + s)
						continue
					}
					if bytes.Compare(expected.(*Server.PIREntryBenchmark).Coalesce(), answerPt) != 0 {
						fmt.Println("Want")
						fmt.Println(expected.(*Server.PIREntryBenchmark).Value)
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

					records := fmt.Sprintf("%d, %d, %d, %d, %d, %f, %d, %f, %d, %f,%d,  %f, %f, %f, %f, %f", entries, size/8, maxEntries, dimentions, logN, ecdTime, ecdSize, queryGenTime, querySize, answerGenTime, answerSize, answerGetTime, ecdTime+queryGenTime+answerGenTime+answerGetTime, queryGenTime+answerGenTime+answerGetTime, leakedBits, math.Log2(float64(entries)))
					err = csvW.Write(strings.Split(records, ","))
					if err != nil {
						t.Logf(err.Error())
					}
					csvW.Flush()
					err = csvW.Error()
					if err != nil {
						t.Logf(err.Error())
					}
					records = fmt.Sprintf("Entries : %d, Size : %d, Max Entries: %d, Dimentions : %d, N: %d, Ecd Time : %f, Ecd Size : %d, Query Gen Time : %f,Query Size : %d, Answer Gen Time : %f, Answer Size : %d, Answer Get Time : %f, Tot Time : %f, Online Time: %f, Leaked Bits : %f / %f", entries, size/8, maxEntries, dimentions, logN, ecdTime, ecdSize, queryGenTime, querySize, answerGenTime, answerSize, answerGetTime, ecdTime+queryGenTime+answerGenTime+answerGetTime, queryGenTime+answerGenTime+answerGetTime, leakedBits, math.Log2(float64(entries)))
					log.Println(records)
				}
			}
		}
	}
}

func TestClientRetrieval(t *testing.T) {
	//DB dimentions
	log.Println("Starting test. NumThreads = ", runtime.NumCPU())
	testCases := []struct {
		name          string
		path          string
		expansion     bool
		weaklyPrivate bool
		leakage       int
	}{
		//{"No Expansion", DIR + "pirGo.csv", false, false, pir.NONELEAKAGE},
		{"Expansion", DIR + "pirGoExp2.csv", true, false, messages.NONELEAKAGE},
		{"WPIR STD", DIR + "pirGoWP2.csv", true, true, messages.STANDARDLEAKAGE},
		{"WPIR HIGH", DIR + "pirGoWP2.csv", true, true, messages.HIGHLEAKAGE},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testClientRetrieval(t, tc.path, tc.expansion, tc.weaklyPrivate, tc.leakage)
		})
	}
}
