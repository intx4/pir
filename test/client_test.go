// Package implements unit test for testing functionalities and benchmarking. Disclaimer: test suite has not full coverage
package test

import (
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/benchmark/latency"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	Client "pir/client"
	"pir/messages"
	Server "pir/server"
	"pir/settings"
	"pir/utils"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

var Mb = 1048576.0
var DEBUG = true
var DIR = os.ExpandEnv("$HOME/pir/test/data/")
var ListOfEntries = []int{1 << 18, 1 << 20, 1 << 22}
var Sizes = []int{288 * 8} //bits
var enableTLS = true       //true to test with TLS baseline
// from TS 22.261 table 7.1-1
var DLSpeeds = []float64{(10.0) * Mb, (25.0) * Mb, (50.0) * Mb, (300.0) * Mb}

func testDownloadTLS(t *testing.T, entries, size, dl float64) float64 {
	latencyOpts := &latency.Network{
		Kbps:    int(dl/Mb) * 1000,
		Latency: 50 * time.Millisecond,
		MTU:     1500,
	}
	file := RandByteString(int(math.Ceil(entries * size / 8)))

	// Create server
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Disposition", "attachment; filename=test.csv")
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.FormatInt(int64(len(file)), 10))
			w.Header().Set("Connection", "close")
			w.Header().Set("Expires", "-1")
			buf := bytes.NewReader(file)
			io.Copy(w, buf)
		}),
	}

	// Start server
	ln, err := net.Listen("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Error starting server: %v", err)
	}
	lnLatency := latencyOpts.Listener(ln)
	fmt.Println("Starting server TLS at...", serverAddr)
	go func() {
		err := server.ServeTLS(lnLatency, "./data/server.crt", "./data/server.key")
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf(err.Error())
		} else {
			fmt.Println("Server listening")
		}
	}()

	// create a client with TLS
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, address string) (net.Conn, error) {
				c, err := net.Dial("tcp", serverAddr)
				if err != nil {
					return nil, err
				}
				conn, err := latencyOpts.Conn(c)
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// download the file from the server
	fmt.Println("Client retrieving file of size (GB):", float64(len(file))/1e9)
	time.Sleep(1 * time.Second)
	start := time.Now()
	resp, err := client.Get("https://" + serverAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	if len(body) < len(file) {
		t.Fatalf("body if less then file")
	}
	end := time.Since(start).Seconds()
	records := fmt.Sprintf("Entries=%f, Size=%f, Time=%f, BW (Mb)=%f", entries, size/8, end, (dl)/Mb)
	log.Println(records)
	server.Close()
	return end
}

func testClientRetrieval(t *testing.T, path string, expansion bool, weaklyPrivate bool, leakage int, brokenParams *map[string]struct{}) {
	logger := logrus.New()

	// Set the output to os.Stdout
	logger.Out = os.Stdout

	// Set the formatter to include colors
	logger.Formatter = &logrus.TextFormatter{
		ForceColors: true,
	}

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

	headers := []string{"entries", "size", "dimentions", "N", "ecd_time", "ecd_size", "query_gen_time", "query_size", "query_size_no_evt_keys", "answer_gen_time", "answer_size", "answer_get_time", "online_time", "online_time_no_evt_keys", "baseline", "withTLS", "DL", "UL", "leakedBits", "informationBits"}
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
		//if entries > 1<<26 && !weaklyPrivate {
		//	continue
		//}
		for _, size := range Sizes {
			//fake db
			//if size > 288 && entries > 1<<26 {
			//	continue
			//}
			//if !weaklyPrivate && (entries >= 1<<27 && size >= 1000) {
			//	continue
			//}
			db := make([][]byte, entries)
			for i := 0; i < entries; i++ {
				db[i] = make([]byte, size/8)
				db[i] = RandByteString(size / 8)
			}

			for _, logN := range []int{13} {
				for _, dimentions := range []int{2, 3} {
					//if !weaklyPrivate && ((logN == 14 || (logN == 13 && dimentions > 2)) && entries >= 1<<25 && size >= 1000) {
					//	continue
					//}
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

					choice := rand.Int() % ctx.K
					start = time.Now()
					query, leakedBits, err := client.QueryGen(choice, profile, leakage, weaklyPrivate, expansion, true)
					if err != nil {
						t.Fatalf(err.Error())
					}
					queryGenTime := time.Since(start).Seconds()
					choosenKey, _ := utils.Decompose(choice, ctx.Kd, ctx.Dim)
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
						t.Logf(fmt.Sprintf("Broken set of params < %s > -- items: %d, size: %d", s, entries, size))
						(*brokenParams)[s] = struct{}{}
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
					for i := 0; i < len(DLSpeeds); i++ {
						DLSpeed := DLSpeeds[i]
						queryUploadCost := float64(querySize*8) / DLSpeed
						queryNoEvtKeysUploadCost := float64(querySizeNoEvtKeys*8) / DLSpeed
						downloadCost := float64(answerSize*8) / DLSpeed
						privacyBits := math.Log2(float64(entries)) - leakedBits
						baseLine := ((math.Pow(2.0, privacyBits))*float64(size))/DLSpeed + (64.0 / DLSpeed) //index int64
						withTLS := 0
						if baseLine <= 60*10.0 && enableTLS {
							log.Println("Testing with TLS")
							baseLine = testDownloadTLS(t, math.Pow(2.0, privacyBits), float64(size), DLSpeed)
							withTLS = 1
						}
						//add 50ms of latency
						onlineTime := queryGenTime + answerGenTime + answerGetTime + queryUploadCost + downloadCost + 2.0*(50.0/1000.0)
						onlineTimeNoKeys := onlineTime - queryUploadCost + queryNoEvtKeysUploadCost + 2.0*(50.0/1000.0)
						//{"entries", "size", "dimentions", "LogN", "ecd_time", "ecd_size", "query_gen_time", "query_size", "query_size_no_evt_keys", "answer_gen_time", "answer_size", "answer_get_time", "online_time", "online_time_no_evt_keys", "baseline", "leakedBits", "informationBits"}
						records := fmt.Sprintf("%d, %d, %d, %d, %f, %d, %f, %d, %d, %f, %d, %f, %f, %f, %f, %d, %f, %f, %f, %f", entries, size/8, dimentions, logN, ecdTime, ecdSize, queryGenTime, querySize, querySizeNoEvtKeys, answerGenTime, answerSize, answerGetTime, onlineTime, onlineTimeNoKeys, baseLine, withTLS, DLSpeed/Mb, DLSpeed/Mb, leakedBits, math.Log2(float64(entries)))
						err = csvW.Write(strings.Split(records, ","))
						if err != nil {
							t.Logf(err.Error())
						}
						csvW.Flush()
						err = csvW.Error()
						if err != nil {
							t.Logf(err.Error())
						}
						if onlineTime < baseLine {
							logger.Info(records)
						} else if onlineTimeNoKeys < baseLine {
							logger.Warn(records)
						} else {
							logger.Error(records)
						}
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
		{"Expansion", DIR + "idxpirGoExpTLS.csv", true, false, messages.NONELEAKAGE},
		{"WPIR STD", DIR + "idxpirGoWPTLS.csv", true, true, messages.STANDARDLEAKAGE},
		{"WPIR HIGH", DIR + "idxpirGoWPTLS.csv", true, true, messages.HIGHLEAKAGE},
	}

	for _, tc := range testCases {
		brokenParams := make(map[string]struct{})
		t.Run(tc.name, func(t *testing.T) {
			testClientRetrieval(t, tc.path, tc.expansion, tc.weaklyPrivate, tc.leakage, &brokenParams)
		})
		t.Logf("Broken params for %s :", tc.name)
		for s, _ := range brokenParams {
			t.Logf(s)
		}
		brokenParams = make(map[string]struct{})
	}
}

//testing our context
