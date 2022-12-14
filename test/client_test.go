package test

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
	utils2 "github.com/tuneinsight/lattigo/v4/utils"
	"log"
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

func TestClientQueryGen(t *testing.T) {
	items := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16}
	sizes := []int{150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			for _, dimentions := range []int{2, 3} {
				context, err := settings.NewPirContext(item, size, dimentions, 13, 65537, 16, true)
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
				profile, err := client.GenProfile()
				if err != nil {
					t.Fatalf(err.Error())
				}
				sampler, err := pir.NewSampler(profile.Seed, client.Box.Params)
				if err != nil {
					t.Fatalf(err.Error())
				}
				for d, di := range choosenIdx {
					q := query[d]
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

// When encrypting with sk the ciphertext consists of a tuple
// where one element is sampled at random -> we can subsitute a polynomial with a random seed and
// let the server regenerate it
func TestCompressionOfCt(t *testing.T) {
	params, _ := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN: 13,
		LogQ: settings.QI[2][1<<13],
		T:    uint64(65537),
	})

	t.Run("encoding/slots", func(t *testing.T) {
		box := settings.HeBox{
			Params: params,
			Sk:     nil,
			Pk:     nil,
			Kgen:   bfv.NewKeyGenerator(params),
			Ecd:    bfv.NewEncoder(params),
			Enc:    nil,
			Dec:    nil,
			Evt:    nil,
		}
		sk := box.Kgen.GenSecretKey()
		rand.Seed(123)
		keyPRNG := make([]byte, 64)
		rand.Read(keyPRNG)
		prng, err := utils2.NewKeyedPRNG(keyPRNG)
		if err != nil {
			t.Fatalf(err.Error())
		}
		box.Enc = bfv.NewPRNGEncryptor(params, sk).WithPRNG(prng)
		box.Ecd = bfv.NewEncoder(params)
		box.Dec = bfv.NewDecryptor(params, sk)
		ct := box.Enc.EncryptNew(box.Ecd.EncodeNew([]uint64{1, 2, 3}, params.MaxLevel()))

		// c0 := ct.Value[0]
		prng2, _ := utils2.NewKeyedPRNG(keyPRNG)
		sampler := ringqp.NewUniformSampler(prng2, *params.RingQP())
		ct2 := bfv.NewCiphertext(params, ct.Degree(), ct.Level())
		sampler.ReadLvl(ct.Level(), -1, ringqp.Poly{Q: ct2.Value[1]})
		ct2.MetaData = ct.MetaData
		params.RingQ().InvNTTLvl(ct2.Level(), ct2.Value[1], ct2.Value[1])
		ct2.Value[0] = ct.Value[0]
		fmt.Println(box.Ecd.DecodeUintNew(box.Dec.DecryptNew(ct2)))
	})
	t.Run("encoding/coeffs", func(t *testing.T) {
		box := settings.HeBox{
			Params: params,
			Sk:     nil,
			Pk:     nil,
			Kgen:   bfv.NewKeyGenerator(params),
			Ecd:    bfv.NewEncoder(params),
			Enc:    nil,
			Dec:    nil,
			Evt:    nil,
		}
		sk := box.Kgen.GenSecretKey()
		rand.Seed(123)
		keyPRNG := make([]byte, 64)
		rand.Read(keyPRNG)
		prng, err := utils2.NewKeyedPRNG(keyPRNG)
		if err != nil {
			t.Fatalf(err.Error())
		}
		box.Enc = bfv.NewPRNGEncryptor(params, sk).WithPRNG(prng)
		box.Ecd = bfv.NewEncoder(params)
		box.Dec = bfv.NewDecryptor(params, sk)
		ct := box.Enc.EncryptNew(utils.EncodeCoeffs(box.Ecd, params, []uint64{1, 2, 3}))
		//prng2, _ := utils2.NewKeyedPRNG(keyPRNG)
		//sampler := ringqp.NewUniformSampler(prng2, *params.RingQP())
		//ct2 := bfv.NewCiphertext(params, ct.Degree(), ct.Level())
		//sampler.ReadLvl(ct.Level(), -1, ringqp.Poly{Q: ct2.Value[1]})
		//ct2.MetaData = ct.MetaData
		//ct2.Value[0] = ct.Value[0]
		sampler, _ := pir.NewSampler(123, box.Params)

		// |
		// v to make this work, comment out the InvNTT in DecompressCT in case *rlwe.Ciphertext

		ct2, _ := pir.DecompressCT(pir.CompressCT(ct), *sampler, box.Params)
		utils.ShowCoeffs(ct2.(*rlwe.Ciphertext), box)
	})

}

/*
func TestCircuitWithLateModSwitch(t *testing.T) {
	params, _ := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN: 12,
		LogQ: settings.QI[2][1<<12],
		LogP: nil,
		T:    uint64(65537),
	})
	box := settings.HeBox{
		Params: params,
		Sk:     nil,
		Pk:     nil,
		Kgen:   bfv.NewKeyGenerator(params),
		Ecd:    bfv.NewEncoder(params),
		Enc:    nil,
		Dec:    nil,
		Evt:    nil,
	}
	sk, pk := box.Kgen.GenKeyPair()
	box.Sk = sk
	box.Pk = pk
	rlk, _ := box.GenRelinKey()
	box.Evt = bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	box.Enc = bfv.NewEncryptor(params, pk)
	box.Dec = bfv.NewDecryptor(params, sk)

	selector := make([]uint64, params.N())
	for i := range selector {
		selector[i] = 1
	}
	selectorEnc := box.Enc.EncryptNew(box.Ecd.EncodeNew(selector, params.MaxLevel())) //budget = log(q) - log(t) = 43

	data := make([]uint64, params.N())
	for i := range data {
		data[i] = uint64(i) + 1
	}
	dataEcd := box.Ecd.EncodeMulNew(data, params.MaxLevel())
	selected1 := box.Evt.MulNew(selectorEnc, dataEcd) //budget = 43 - log(t/2) = 27

	fmt.Println("First mul")
	value := selected1.GetScale().Value
	fmt.Println(value.String())
	dec := box.Ecd.DecodeUintNew(box.Dec.DecryptNew(selected1))
	fmt.Println(dec)

	//accumulator
	//budget = 27 - log(sums) = 19
	for i := 0; i < 256; i++ {
		r := box.Enc.EncryptZeroNew(params.MaxLevel())
		box.Evt.Add(selected1, r, selected1)
	}
	fmt.Println("First accumul")
	dec = box.Ecd.DecodeUintNew(box.Dec.DecryptNew(selected1))
	fmt.Println(dec)

	selected2 := box.Evt.MulNew(selectorEnc, selected1) //budget = 19 - log(2tNN) = 19 - (1 + 17 + 24)

	fmt.Println("Second mul")
	dec = box.Ecd.DecodeUintNew(box.Dec.DecryptNew(selected2))
	fmt.Println(dec)
	//accumulator
	for i := 0; i < 256; i++ {
		r := box.Enc.EncryptZeroNew(params.MaxLevel())
		box.Evt.Add(selected2, r, selected2)
	}
	fmt.Println("Second accum")
	dec = box.Ecd.DecodeUintNew(box.Dec.DecryptNew(selected2))
	fmt.Println(dec)

	box.Evt.Relinearize(selected2, selected2)
	//	box.Evt.Rescale(selected2, selected2)
	dec = box.Ecd.DecodeUintNew(box.Dec.DecryptNew(selected2))
	fmt.Println(dec)

}
*/

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
					query, err := client.CompressedQueryGen(keys[choice])
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
					for _, q := range query {
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
