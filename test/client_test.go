// Package implements unit test for testing functionalities and benchmarking. Disclaimer: test suite has not full coverage
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

var Mb = 1048576.0
var DEBUG = true
var DIR = os.ExpandEnv("$HOME/pir/test/data/")
var ListOfEntries = []int{1 << 16, 1 << 27, 1 << 26, 1 << 24, 1 << 20}
var Sizes = []int{1000 * 8, 288 * 8, 30 * 8} //bits

// from TS 22.261 table 7.1-1
var DLSpeeds = []float64{(25.0) * Mb, (50.0) * Mb, (300.0) * Mb, (1000.0) * Mb}
var ULSpeeds = []float64{(50.0) * Mb, (25.0) * Mb, (50.0) * Mb, (500.0) * Mb}

func testClientRetrieval(t *testing.T, path string, expansion bool, weaklyPrivate bool, leakage int, brokenParams *[]string) {
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

	headers := []string{"entries", "size", "dimentions", "N", "ecd_time", "ecd_size", "query_gen_time", "query_size", "query_size_no_evt_keys", "answer_gen_time", "answer_size", "answer_get_time", "online_time", "online_time_no_evt_keys", "baseline", "DL", "UL", "leakedBits", "informationBits"}
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
			for _, logN := range []int{12, 13, 14} {
				for _, dimentions := range []int{2, 3} {
					if size > 288 && logN == 12 {
						continue
					}
					if size > 288 && entries > 1<<24 {
						continue
					}
					if size >= 1<<27 && !weaklyPrivate {
						continue
					}
					log.Println(fmt.Sprintf("Testing %d entries of %d bytes, logN %d, dim %d", entries, size/8, logN, dimentions))
					//first we create some parameters
					paramsId, params := settings.GetsParamForPIR(logN, dimentions, expansion, weaklyPrivate, leakage)
					ctx, err := settings.NewPirContext(entries, size, params.N(), dimentions)
					if err != nil {
						t.Logf(err.Error())
						continue
					}
					//create a server -> server will encode the DB in an hypercube following the context
					start := time.Now()
					server, err := Server.NewPirServer(ctx, db)
					ecdTime := time.Since(start).Seconds()
					if err != nil {
						t.Fatalf(err.Error())
					}
					//now we create a new pir instance
					client := Client.NewPirClient("TEST")
					if err != nil {
						t.Fatalf(err.Error())
					}

					//client needs to fetch the context as it is not aware of it
					ctxReq := client.ContextReqGen()
					ctxAns, err := server.Answer(ctxReq)
					if err != nil {
						t.Fatalf(err.Error())
					}
					if ctxAns.FetchContext && ctxAns.Ok {
						client.AddContext(ctxAns.Context)
					} else {
						t.Fatalf("Could not fetch context")
					}

					//after setting the context we can generate a profile
					profile, err := client.GenProfile(params, paramsId)

					choice := rand.Int() % len(keys)
					start = time.Now()
					query, leakedBits, err := client.QueryGen([]byte(keys[choice]), profile, leakage, weaklyPrivate, expansion, true)
					if err != nil {
						t.Fatalf(err.Error())
					}
					queryGenTime := time.Since(start).Seconds()
					choosenKey, _ := utils.MapKeyToDim([]byte(keys[choice]), ctx.Kd, ctx.Dim)
					if err != nil {
						t.Fatalf(err.Error())
					}
					expected, _ := server.Store.Load(choosenKey)
					ecdSize := 0
					server.Store.Range(func(key, value any) bool {
						serialized, err := json.Marshal(value.(*Server.PIRDBEntry))
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
					answer, err := server.Answer(query)
					if err != nil {
						t.Fatalf(err.Error())
					}
					answerGenTime := time.Since(start).Seconds()

					if !answer.Ok || answer.Answer == nil {
						t.Fatalf(answer.Error)
					}
					//extract the answer
					start = time.Now()
					answerPt, err := client.AnswerGet(profile, answer.Answer)
					answerGetTime := time.Since(start).Seconds()

					if err != nil {
						t.Logf(err.Error())
						s, _ := settings.GetsParamForPIR(logN, dimentions, expansion, weaklyPrivate, leakage)
						t.Logf("Broken set of params: " + s)
						*brokenParams = append(*brokenParams, s)
						continue
					}
					if bytes.Compare(expected.(*Server.PIRDBEntry).Coalesce(), answerPt) != 0 {
						fmt.Println("Want")
						fmt.Println(expected.(*Server.PIRDBEntry).Value)
						fmt.Println("Got")
						fmt.Println(answerPt)
						t.Fatalf("Answer does not match expected")
					}

					querySize := 0
					querySizeNoEvtKeys := 0
					if query.Q.Compressed != nil {
						for _, q := range query.Q.Compressed {
							bin, _ := q.MarshalBinary()
							querySize += len(bin)
							querySizeNoEvtKeys += len(bin)
						}
					} else if query.Q.Expanded != nil {
						for _, Q := range query.Q.Expanded {
							for _, q := range Q {
								bin, _ := q.MarshalBinary()
								querySize += len(bin)
								querySizeNoEvtKeys += len(bin)
							}
						}
					}
					bin, _ := query.Profile.Rlk.MarshalBinary()
					querySize += len(bin)
					bin, _ = query.Profile.Rtks.MarshalBinary()
					querySize += len(bin)

					answerSize := 0
					for _, a := range answer.Answer {
						serialized, err := a.MarshalBinary()
						answerSize += len(serialized)
						if err != nil {
							t.Fatalf(err.Error())
						}
					}
					for i := 0; i < len(ULSpeeds); i++ {
						ULSpeed, DLSpeed := ULSpeeds[i], DLSpeeds[i]
						queryUploadCost := float64(querySize*8) / ULSpeed
						queryNoEvtKeysUploadCost := float64(querySizeNoEvtKeys*8) / ULSpeed
						downloadCost := float64(answerSize*8) / DLSpeed
						privacyBits := math.Log2(float64(entries)) - leakedBits
						baseLine := ((math.Pow(2.0, privacyBits))*float64(size))/DLSpeed + (64.0 / ULSpeed) //index int64
						onlineTime := queryGenTime + answerGenTime + answerGetTime + queryUploadCost + downloadCost
						onlineTimeNoKeys := onlineTime - queryUploadCost + queryNoEvtKeysUploadCost
						//{"entries", "size", "dimentions", "LogN", "ecd_time", "ecd_size", "query_gen_time", "query_size", "query_size_no_evt_keys", "answer_gen_time", "answer_size", "answer_get_time", "online_time", "online_time_no_evt_keys", "baseline", "leakedBits", "informationBits"}
						records := fmt.Sprintf("%d, %d, %d, %d, %f, %d, %f, %d, %d, %f, %d, %f, %f, %f, %f,%f, %f, %f, %f", entries, size/8, dimentions, logN, ecdTime, ecdSize, queryGenTime, querySize, querySizeNoEvtKeys, answerGenTime, answerSize, answerGetTime, onlineTime, onlineTimeNoKeys, baseLine, DLSpeed/Mb, ULSpeed/Mb, leakedBits, math.Log2(float64(entries)))
						err = csvW.Write(strings.Split(records, ","))
						if err != nil {
							t.Logf(err.Error())
						}
						csvW.Flush()
						err = csvW.Error()
						if err != nil {
							t.Logf(err.Error())
						}
						log.Println(records)
					}
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
		{"Expansion", DIR + "pirGoExp.csv", true, false, messages.NONELEAKAGE},
		{"WPIR STD", DIR + "pirGoWP.csv", true, true, messages.STANDARDLEAKAGE},
		{"WPIR HIGH", DIR + "pirGoWP.csv", true, true, messages.HIGHLEAKAGE},
	}
	brokenParams := make([]string, 0)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testClientRetrieval(t, tc.path, tc.expansion, tc.weaklyPrivate, tc.leakage, &brokenParams)
		})
		t.Logf("Broken params for %s :", tc.name)
		for _, s := range brokenParams {
			t.Logf(s)
		}
	}
	t.Logf("Broken params:")
	for _, s := range brokenParams {
		t.Logf(s)
	}
}
