package test

import (
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"math/rand"
	"pir"
	"pir/settings"
	"pir/utils"
	"testing"
)

var DEBUG = true

func TestClientQueryGenNoExpansion(t *testing.T) {
	items := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16}
	sizes := []int{30 * 8, 150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			//fake db
			keys := make([][]byte, item)
			values := make([][]byte, item)
			for i := range keys {
				keys[i] = RandByteString(100)
				values[i] = RandByteString(size)
			}
			for _, dimentions := range []int{2, 3} {
				for _, logN := range []int{13, 14} {
					//first we create some parameters
					box, err := settings.NewHeBox(logN, dimentions, false)
					if err != nil {
						t.Fatalf(err.Error())
					}
					//now we create a new client instance
					client := pir.NewPirClient(box, "007")

					//the client should provide the params to the server
					//the server here creates a context using the info about the DB and params
					ctx, err := settings.NewPirContext(item, size, box.Params)
					if err != nil {
						t.Fatalf(err.Error())
					}
					choice := rand.Int() % len(keys)
					query, err := client.QueryGen(keys[choice], ctx, dimentions, false, false)
					if err != nil {
						t.Fatalf(err.Error())
					}
					_, choosenIdx := utils.MapKeyToDim(keys[choice], query.Kd, query.Dimentions)

					//this part is actually done at server
					sampler, err := pir.NewSampler(query.Seed, client.Box.Params)
					if err != nil {
						t.Fatalf(err.Error())
					}
					for d, di := range choosenIdx {
						q := query.Q.([][]*pir.PIRQueryCt)[d]
						for i, ctc := range q {
							ct, err := pir.DecompressCT(ctc, *sampler, client.Box.Params)
							if err != nil {
								t.Fatalf(err.Error())
							}
							pt := client.Box.Dec.DecryptNew(ct.(*rlwe.Ciphertext))
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
}

func TestClientQueryGenWithExpansion(t *testing.T) {
	items := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16}
	sizes := []int{30 * 8, 150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			//fake db
			keys := make([]string, item)
			values := make([][]byte, item)
			db := make(map[string][]byte)
			for i := 0; i < len(keys); {
				keys[i] = string(RandByteString(100))
				values[i] = RandByteString(size)
				if _, ok := db[keys[i]]; !ok {
					db[keys[i]] = values[i]
					i++
				}
			}
			for _, dimentions := range []int{2, 3} {
				for _, logN := range []int{13, 14} {
					//first we create some parameters
					box, err := settings.NewHeBox(logN, dimentions, true)
					if err != nil {
						t.Fatalf(err.Error())
					}
					//now we create a new client instance
					client := pir.NewPirClient(box, "007")
					//now we create a profile which contains all the params and keys needed to server
					profile, err := client.GenProfile()
					if err != nil {
						t.Fatalf(err.Error())
					}
					server := pir.NewPirServer(db)
					err = server.WithProfile(profile)
					if err != nil {
						t.Fatalf(err.Error())
					}
					//now the server is able to create a context with the params provided by client
					ctx, err := settings.NewPirContext(item, size, box.Params)
					if err != nil {
						t.Fatalf(err.Error())
					}
					choice := rand.Int() % len(keys)
					query, err := client.QueryGen([]byte(keys[choice]), ctx, dimentions, false, true)
					if err != nil {
						t.Fatalf(err.Error())
					}
					_, choosenIdx := utils.MapKeyToDim([]byte(keys[choice]), query.Kd, query.Dimentions)

					//this part is actually done at server
					sampler, err := pir.NewSampler(query.Seed, client.Box.Params)
					if err != nil {
						t.Fatalf(err.Error())
					}

					queryDecomp, err := pir.DecompressCT(query.Q, *sampler, box.Params)
					if err != nil {
						t.Fatalf(err.Error())
					}

					queryExpanded, err := server.ObliviousExpand(queryDecomp.([]*rlwe.Ciphertext), profile.Rtks, query.Dimentions, query.Kd)
					for d, di := range choosenIdx {
						q := queryExpanded[d]
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
}

func TestClientQueryWithDifferentialObliviousness(t *testing.T) {
	items := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16}
	sizes := []int{30 * 8, 150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			//fake db
			keys := make([]string, item)
			values := make([][]byte, item)
			db := make(map[string][]byte)
			for i := 0; i < len(keys); {
				keys[i] = string(RandByteString(100))
				values[i] = RandByteString(size)
				if _, ok := db[keys[i]]; !ok {
					db[keys[i]] = values[i]
					i++
				}
			}
			for _, dimentions := range []int{2, 3} {
				for _, logN := range []int{13, 14} {
					//first we create some parameters
					box, err := settings.NewHeBox(logN, dimentions, true)
					if err != nil {
						t.Fatalf(err.Error())
					}
					//now we create a new client instance
					client := pir.NewPirClient(box, "007")
					err = client.WithDifferentialOblviousness(0.01, 1e-4, 1)
					if err != nil {
						t.Fatalf(err.Error())
					}
					//now we create a profile which contains all the params and keys needed to server
					profile, err := client.GenProfile()
					if err != nil {
						t.Fatalf(err.Error())
					}
					server := pir.NewPirServer(db)
					err = server.WithProfile(profile)
					if err != nil {
						t.Fatalf(err.Error())
					}
					//now the server is able to create a context with the params provided by client
					ctx, err := settings.NewPirContext(item, size, box.Params)
					if err != nil {
						t.Fatalf(err.Error())
					}
					choice := rand.Int() % len(keys)
					query, err := client.QueryGen([]byte(keys[choice]), ctx, dimentions, true, true)
					if err != nil {
						t.Fatalf(err.Error())
					}
					_, choosenIdx := utils.MapKeyToDim([]byte(keys[choice]), query.Kd, query.Dimentions)

					//this part is actually done at server
					sampler, err := pir.NewSampler(query.Seed, client.Box.Params)
					if err != nil {
						t.Fatalf(err.Error())
					}

					queryDecomp, err := pir.DecompressCT(query.Q, *sampler, box.Params)
					if err != nil {
						t.Fatalf(err.Error())
					}

					queryExpanded, err := server.ObliviousExpand(queryDecomp.([]*rlwe.Ciphertext), profile.Rtks, query.Dimentions, query.Kd)
					for d, di := range choosenIdx {
						q := queryExpanded[d]
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
}

/*
func TestClientRetrieval(t *testing.T) {
	//DB dimentions
	os.Chdir(os.ExpandEnv("$HOME/pir"))
	log.Println("Starting test. NumThreads = ", runtime.NumCPU())

	listOfEntries := []int{1 << 14, 1 << 16, 1 << 18, 1 << 20}
	sizes := []int{30 * 8, 188 * 8, 288 * 8}

	path := os.ExpandEnv("$HOME/pir/data/pirGo.csv")
	os.Remove(path)
	csvFile, err := os.Create(path)
	if err != nil {
		t.Fatalf(err.Error())
	}
	csvW := csv.NewWriter(csvFile)

	defer csvFile.Close()

	headers := []string{"entries", "size", "d", "n", "ecd_time", "ecd_size", "query_gen_time", "answer_gen_time", "answer_get_time", "tot_time", "query_size", "answer_size"}
	csvW.Write(headers)

	for _, entries := range listOfEntries {
		for _, size := range sizes {
			for _, dimentions := range []int{2} {
				for _, n := range []int{13, 14} {
					//first we create a context for the PIR
					if dimentions == 3 && n == 12 {
						continue
					}
					context, err := settings.NewPirContext(entries, size, dimentions, n, 65537, 16, false)
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
					query, err := client.QueryGen(keys[choice], false)
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
					profile, err := client.GenProfile()
					if err != nil {
						t.Fatalf(err.Error())
					}
					start = time.Now()
					answerEnc, err := server.AnswerGen(ecdStorage, query, profile)
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
					for _, q := range query.([][]*pir.PIRQueryCt) {
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

					records := fmt.Sprintf("%d, %d, %d, %d, %f, %d, %f, %f, %f, %f, %d, %d", entries, size/8, dimentions, n, ecdTime, ecdSize, queryGenTime, answerGenTime, answerGetTime, ecdTime+queryGenTime+answerGenTime+answerGetTime, querySize, answerSize)
					err = csvW.Write(strings.Split(records, ","))
					if err != nil {
						t.Logf(err.Error())
					}
					csvW.Flush()
					err = csvW.Error()
					if err != nil {
						t.Logf(err.Error())
					}
					records = fmt.Sprintf("Entries : %d, Size : %d, Dimentions : %d, N: %d, Ecd Time : %f, Ecd Size : %d, Query Gen Time : %f, Answer Gen Time : %f, Answer Get Time : %f, Tot Time : %f, Query Size : %d, Answer Size : %d", entries, size/8, dimentions, n, ecdTime, ecdSize, queryGenTime, answerGenTime, answerGetTime, ecdTime+queryGenTime+answerGenTime+answerGetTime, querySize, answerSize)
					log.Println(records)
				}
			}
		}
	}
}

func TestClientRetrievalWithObliviousExpansion(t *testing.T) {
	//DB dimentions
	os.Chdir(os.ExpandEnv("$HOME/pir"))
	log.Println("Starting test. NumThreads = ", runtime.NumCPU())

	listOfEntries := []int{1 << 14, 1 << 16, 1 << 18, 1 << 20}
	sizes := []int{30 * 8, 188 * 8, 288 * 8}
	path := os.ExpandEnv("$HOME/pir/data/pirGoOblivious.csv")
	os.Remove(path)
	csvFile, err := os.Create(path)
	if err != nil {
		t.Fatalf(err.Error())
	}
	csvW := csv.NewWriter(csvFile)

	defer csvFile.Close()

	headers := []string{"entries", "size", "d", "n", "ecd_time", "ecd_size", "query_gen_time", "answer_gen_time", "answer_get_time", "tot_time", "query_size", "answer_size"}
	csvW.Write(headers)

	for _, entries := range listOfEntries {
		for _, size := range sizes {
			for _, dimentions := range []int{2} {
				for _, n := range []int{13, 14} {
					//first we create a context for the PIR
					if dimentions == 3 && n == 12 {
						continue
					}
					context, err := settings.NewPirContext(entries, size, dimentions, n, 65537, 16, true)
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
					query, err := client.QueryGen(keys[choice], true)
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

					if DEBUG {
						server.Box.Dec = client.Box.Dec
					}
					profile, err := client.GenProfile()

					if err != nil {
						t.Fatalf(err.Error())
					}
					start = time.Now()
					answerEnc, err := server.AnswerGen(ecdStorage, query, profile)
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
					for _, q := range query.([]*pir.PIRQueryCt) {
						serialized, err := q.MarshalBinary()
						querySize += len(serialized)
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

					records := fmt.Sprintf("%d, %d, %d, %d, %f, %d, %f, %f, %f, %f, %d, %d", entries, size/8, dimentions, n, ecdTime, ecdSize, queryGenTime, answerGenTime, answerGetTime, ecdTime+queryGenTime+answerGenTime+answerGetTime, querySize, answerSize)
					err = csvW.Write(strings.Split(records, ","))
					if err != nil {
						t.Logf(err.Error())
					}
					csvW.Flush()
					err = csvW.Error()
					if err != nil {
						t.Logf(err.Error())
					}
					records = fmt.Sprintf("Entries : %d, Size : %d, Dimentions : %d, N: %d, Ecd Time : %f, Ecd Size : %d, Query Gen Time : %f, Answer Gen Time : %f, Answer Get Time : %f, Tot Time : %f, Query Size : %d, Answer Size : %d", entries, size/8, dimentions, n, ecdTime, ecdSize, queryGenTime, answerGenTime, answerGetTime, ecdTime+queryGenTime+answerGenTime+answerGetTime, querySize, answerSize)
					log.Println(records)
				}
			}
		}
	}
}
*/
