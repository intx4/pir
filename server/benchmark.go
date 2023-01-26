package server

import (
	"errors"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"log"
	"math"
	"pir"
	"pir/settings"
	"pir/utils"
	"runtime"
	"strconv"
	"sync"
)

type PIREntryBenchmark struct {
	Items int      `json:"items,omitempty"`
	Value [][]byte `json:"value,omitempty"`
	L     int      `json:"l,omitempty"`
}

type PIRStorageBenchmark struct {
	Mux sync.RWMutex
	Map map[string][]rlwe.Operand `json:"map,omitempty"`
}

func NewPirStorageBenchmark() *PIRStorageBenchmark {
	storage := new(PIRStorageBenchmark)
	storage.Mux = sync.RWMutex{}
	storage.Map = make(map[string][]rlwe.Operand)
	return storage
}

func (S *PIRStorageBenchmark) Load(key interface{}) (interface{}, bool) {
	S.Mux.RLock()
	defer S.Mux.RUnlock()
	v, ok := S.Map[key.(string)]
	return v, ok
}

func NewPirEntryBenchmark(value []byte) *PIREntryBenchmark {
	return &PIREntryBenchmark{Items: 1, Value: [][]byte{value}, L: len(value)}
}

func (PE *PIREntryBenchmark) Update(newValue []byte, maxBinSize int) (int, error) {
	if len(newValue) != PE.L {
		return -1, errors.New(fmt.Sprintf("Byte length of data stored in this entry is not uniform. Old %d, new %d", PE.L, len(newValue)))
	}
	if PE.Items+1 > maxBinSize {
		PE.Value = append(PE.Value, newValue)
		PE.Items++
		return len(PE.Value) - 1, errors.New(fmt.Sprintf("Entry size exceeded maximum bin size: %d > %d", PE.Items, maxBinSize))
	}
	PE.Value = append(PE.Value, newValue)
	PE.Items++
	return len(PE.Value) - 1, nil
}

func (PE *PIREntryBenchmark) Coalesce() []byte {
	v := make([]byte, len(PE.Value)*PE.L+len(PE.Value)-1)
	i := 0
	for iv, b := range PE.Value {
		for _, byt := range b {
			v[i] = byt
			i++
		}
		if iv != len(PE.Value)-1 {
			v[i] = []byte("|")[0]
			i++
		}
	}
	return v
}

func (PE *PIREntryBenchmark) Encode(t int, ecd bfv.Encoder, params bfv.Parameters) ([]rlwe.Operand, error) {
	chunks, err := utils.Chunkify(PE.Coalesce(), t)
	if err != nil {
		return nil, err
	}
	ecdChunks := utils.EncodeChunks(chunks, ecd, params)
	if len(ecdChunks) > 1 {
		log.Println("Bin contains > 1 plaintexts")
	}
	return ecdChunks, nil
}

type PIRServerBenchmark struct {
	Store    *sync.Map
	Profiles map[string]*settings.PIRProfile
}

func NewPirServerBenchmark() *PIRServerBenchmark {
	PS := new(PIRServerBenchmark)
	PS.Store = new(sync.Map)
	PS.Profiles = make(map[string]*settings.PIRProfile)
	return PS
}

func (PS *PIRServerBenchmark) Add(key []byte, value []byte, dimentions, Kd, maxBinSize int) (int, error) {
	k, _ := utils.MapKeyToDim(key, Kd, dimentions)
	if e, ok := PS.Store.Load(k); ok {
		return e.(*PIREntryBenchmark).Update(value, maxBinSize)
	} else {
		PS.Store.Store(k, NewPirEntryBenchmark(value))
		return 1, nil
	}
}

func (PS *PIRServerBenchmark) AddProfile(clientId string, pf *settings.PIRProfile) {
	PS.Profiles[clientId] = pf
}
func (PS *PIRServerBenchmark) WithParams(ctx *settings.PirContext, params bfv.Parameters, clientId string) (*settings.HeBox, error) {
	//set up box from profile
	box := new(settings.HeBox)
	if p, ok := PS.Profiles[clientId]; !ok {
		return nil, errors.New(fmt.Sprintf("%s profile not found", clientId))
	} else {
		box = &settings.HeBox{
			Params: params,
			Ecd:    bfv.NewEncoder(params),
			Evt: bfv.NewEvaluator(params, rlwe.EvaluationKey{
				Rlk:  p.Rlk,
				Rtks: p.Rtks,
			}),
			Rtks: p.Rtks,
			Rlk:  p.Rlk,
		}
		return box, nil
	}
}

// Obliviously expands a compressed query vector. Client must provide rotation keys. Returns an array of interfaces, where each element is either a []*rlwe.Ciphertext or an int that represents the index for that dimention
func (PS *PIRServerBenchmark) ObliviousExpand(query []interface{}, box *settings.HeBox, dimentions, Kd int) ([]interface{}, error) {
	//Procedure 7 from https://eprint.iacr.org/2019/1483.pdf
	evt := rlwe.NewEvaluator(box.Params.Parameters, &rlwe.EvaluationKey{Rtks: box.Rtks})
	if len(query) != dimentions {
		return nil, errors.New(fmt.Sprintf("Query vector has not the right size. Expected %d got %d", dimentions, len(query)))
	}
	logm := int(math.Ceil(math.Log2(float64(Kd))))
	if logm > box.Params.LogN() {
		return nil, errors.New("m > N is not allowed")
	}
	expanded := make([]interface{}, dimentions)
	var err error
	var wg sync.WaitGroup
	for j := range query {
		wg.Add(1)
		go func(j int, evt *rlwe.Evaluator) {
			defer wg.Done()
			switch query[j].(type) {
			case *rlwe.Ciphertext:
				expanded[j] = invNTTforExpand(evt.ShallowCopy().Expand(query[j].(*rlwe.Ciphertext), logm, 0), Kd, box.Params.RingQ())
			case int:
				expanded[j] = query[j]
			default:
				panic(fmt.Sprintf("Unknown type in %T", query[j]))
			}
		}(j, evt)
	}
	wg.Wait()
	return expanded, err
}

// Takes a PIRQuery, Returns an array of interfaces, where each element is either a []*rlwe.Ciphertext or an int that represents the index for that dimention
func (PS *PIRServerBenchmark) ProcessPIRQuery(ctx *settings.PirContext, queryRecvd *pir.PIRQuery, box *settings.HeBox) ([]interface{}, error) {
	var query []interface{} //each entry is either an array of ciphertexts or directly the index to retrieve for this dimention for WPIR
	//Initialize sampler from user seed
	sampler, err := pir.NewSampler(queryRecvd.Seed, box.Params)
	if err != nil {
		return nil, err
	}

	switch queryRecvd.Q.(type) {
	case []*pir.PIRQueryItem:
		var err error
		if box.Rtks == nil {
			return nil, errors.New("Client needs to provide rotation keys for Expand")
		}
		queryDecompressed, err := pir.DecompressCT(queryRecvd.Q, *sampler, box.Params)
		query, err = PS.ObliviousExpand(queryDecompressed, box, ctx.Dim, ctx.Kd)
		if err != nil {
			return nil, err
		}
	case [][]*pir.PIRQueryItem:
		queryDecompressed, err := pir.DecompressCT(queryRecvd.Q, *sampler, box.Params)
		if err != nil {
			return nil, err
		}
		query = queryDecompressed
	default:
		return nil, errors.New(fmt.Sprintf("Query must be []*rlwe.Ciphertext or [][]*rlwe.Ciphertext, not %T", query))
	}
	return query, nil
}

func (PS *PIRServerBenchmark) EncodeBenchmark(ctx *settings.PirContext, query []interface{}, db map[string][]byte) (*sync.Map, error) {
	K, Kd, dimentions := ctx.K, ctx.Kd, ctx.Dim
	maxCollisions := 0
	l := 0
	for _, v := range db {
		l = len(v)
		break
	}
	tooBigErr := ""

	var wg sync.WaitGroup
	pool := runtime.NumCPU()
	poolCh := make(chan struct{}, pool)
	//errCh := make(chan error)
	//init pool chan
	for i := 0; i < pool; i++ {
		poolCh <- struct{}{}
	}
	for key, value := range db {
		if len(value) != l {
			return nil, errors.New(fmt.Sprintf("Not uniform byte length for records: Had %d and now %d", l, len(value)))
		}
		k, coords := utils.MapKeyToDim([]byte(key), Kd, dimentions)
		process := true
		for i := 0; i < int(utils.Min(float64(len(query)), float64(len(coords)))); i++ {
			switch query[i].(type) {
			case int:
				if coords[i] != query[i].(int) {
					process = false
					break
				}
			}
		}
		if !process {
			continue
		}
		<-poolCh
		wg.Add(1)
		go func(key string, value []byte) {
			defer wg.Done()
			if e, ok := PS.Store.LoadOrStore(key, NewPirEntryBenchmark(value)); ok {
				//update
				collisions, err := e.(*PIREntryBenchmark).Update(value, ctx.MaxBinSize)
				if err != nil {
					tooBigErr = err.Error()
				}
				if collisions+1 > maxCollisions {
					maxCollisions = collisions + 1
				}
			}
			poolCh <- struct{}{}
		}(k, value)
	}
	wg.Wait()
	log.Println()
	if tooBigErr != "" {
		fmt.Println("	" + tooBigErr)
	}
	fmt.Printf("		Storage encoded in chunks :\n		Max size of bucket registered = %d / Expected %d --> Max bucket capacity = %d\n		Tot Keys: %d\n", maxCollisions, ctx.ExpBinSize, ctx.MaxBinSize, K)

	ecdStorage := new(sync.Map)
	*ecdStorage = *PS.Store
	return ecdStorage, nil
}

type multiplierTaskBenchmark struct {
	Query      *rlwe.Ciphertext
	Values     interface{}          //from db
	ResultMap  *PIRStorageBenchmark //map to save result of query x values
	ResultKey  string               //key of result map
	FeedBackCh chan int             //flag completion of one mul to caller
}

/*
Given an encoded PIR database and a query from pb, answers the query.
The query can be represented as:
  - a series query vectors of ciphertexts. In each vector (we have d vectors for d dimentions), each ciphertext is Enc(0), but for one
    where ct is Enc(1). If this ct is the ct in position i-th, then you will retrieve all associated to index i for this dimention
  - a series of d ciphertexts. In this case the query goes through an oblivious expansion procedure that generates the same query as case 1
    For every bucket (which consists of N (ring size of BFV) entries, with 1 or more data items), it multiplies the bucket
    with the associated ciphertext in the query.
    After that, all these results get accumulated by summing the results.
    Returns a list of ciphertexts, i.e the answer, which is the result of the accumulation
    between all buckets in the server multiplied by the query. Ideally only one element in a certain bucket will survive
    the selection. The resulting bucket is returned to the pb which can decrypt the answer and retrieve the value
*/
func (PS *PIRServerBenchmark) AnswerGenBenchmark(ecdStore Storage, box *settings.HeBox, query []interface{}, ctx *settings.PirContext) ([]*rlwe.Ciphertext, error) {
	Kd, Dimentions := ctx.Kd, ctx.Dim
	evt := bfv.NewEvaluator(box.Params, rlwe.EvaluationKey{Rlk: box.Rlk})
	ecd := bfv.NewEncoder(box.Params)
	if Kd != len(query[len(query)-1].([]*rlwe.Ciphertext)) {
		return nil, errors.New(fmt.Sprintf("queryExp vector has not the right size. Expected %d got %d", Kd, len(query[len(query)-1].([]*rlwe.Ciphertext))))
	}
	if Dimentions != len(query) {
		return nil, errors.New(fmt.Sprintf("Dimentionality mismatch. Expected %d got %d", Dimentions, len(query)))
	}

	//spawnMultipliers
	taskCh := make(chan multiplierTaskBenchmark, runtime.NumCPU())
	var wg sync.WaitGroup //sync graceful termination
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			SpawnMultiplierBenchmark(evt.ShallowCopy(), ecd.ShallowCopy(), box.Params, taskCh)
		}()
	}

	finalAnswer := make([]*rlwe.Ciphertext, 0)
	for d := 0; d < Dimentions; d++ {
		//loop over all dimentions of the hypercube

		//fmt.Println("dimention ", d+1)
		q := query[d]

		//the idea is to exploit the sync Map for encoding (concurrent writes to disjoint sets of keys)
		//and nextStore for atomic read->add->write
		nextStore := NewPirStorageBenchmark()
		//builds access to storage in a recursive way
		keys := make([]string, 0)
		utils.GenKeysAtDepth("", d+1, Dimentions, Kd, &keys)

		finalRound := d == Dimentions-1

		numEffectiveKeys := 0                          //keeps track of how many entries are effectively in storage at a given dim
		numComputedKeys := 0                           //keeps track of how many query x entry results have been computed in storage at a given dim
		feedbackCh := make(chan int, Kd*(len(keys)+1)) //+1 for final round when len(keys) is 0
		switch q.(type) {
		case []*rlwe.Ciphertext:
			//fmt.Printf("Dimention %d performing mul\n", d+1)
			for di := 0; di < Kd; di++ {
				//scan this dimention
				//fmt.Println("Index: ", di)
				//utils.ShowCoeffs(q[di], *box)
				for _, k := range keys {
					nextK := ""
					if !finalRound {
						nextK = k[1:] //remove "|"
						k = strconv.FormatInt(int64(di), 10) + k
					} else {
						k = strconv.FormatInt(int64(di), 10)
					}
					//feed multipliers
					if e, ok := ecdStore.Load(k); ok {
						numEffectiveKeys++
						//fmt.Printf("Level: %d x %d, depth: %d\n", q[di].Level(), e.([]rlwe.Operand)[0].Level(), d)
						taskCh <- multiplierTaskBenchmark{
							Query:      q.([]*rlwe.Ciphertext)[di],
							Values:     e,
							ResultMap:  nextStore,
							ResultKey:  nextK,
							FeedBackCh: feedbackCh,
						}
					}
				}
			}
		case int:
			//purge all the keys which do not have the right index for dimention
			for _, k := range keys {
				nextK := k[1:] //remove "|"
				k = strconv.FormatInt(int64(q.(int)), 10) + k
				if e, ok := ecdStore.Load(k); ok {
					numEffectiveKeys++
					go func(key string, v interface{}) {
						nextStore.Mux.Lock()
						defer nextStore.Mux.Unlock()
						var err error
						switch v.(type) {
						case *PIREntryBenchmark:
							nextStore.Map[key], err = v.(*PIREntryBenchmark).Encode(settings.TUsableBits, ecd.ShallowCopy(), box.Params)
							if err != nil {
								panic(err.Error())
							}
						case []rlwe.Operand:
							nextStore.Map[key] = v.([]rlwe.Operand)
						default:
							panic(fmt.Sprintf("Unknown type %T", v))
						}
						feedbackCh <- 1
					}(nextK, e)
				}
			}
		}
		//wait for the routines to compute the keys for this di
		for numComputedKeys < numEffectiveKeys {
			numComputedKeys += <-feedbackCh
		}
		//relin and modswitch + recursively update storage
		ecdStore = NewPirStorageBenchmark() //we transform ecdStore into a PIRStorage after first iter to reduce memory
		nextStore.Mux.RLock()
		for key, value := range nextStore.Map {
			for _, ct := range value {
				if d != 0 && ct.Degree() > 1 {
					//after first we have done a ct x pt -> deg is still 1
					evt.Relinearize(ct.(*rlwe.Ciphertext), ct.(*rlwe.Ciphertext))
				}
				if finalRound && key == "" {
					for ct.(*rlwe.Ciphertext).Level() != 0 {
						evt.Rescale(ct.(*rlwe.Ciphertext), ct.(*rlwe.Ciphertext))
					}
					finalAnswer = append(finalAnswer, ct.(*rlwe.Ciphertext))
				}
			}
			if !finalRound {
				ecdStore.(*PIRStorageBenchmark).Map[key] = value
			} else if key == "" {
				break
			}
		}
		nextStore.Mux.RUnlock()
	}
	close(taskCh)
	wg.Wait()
	return finalAnswer, nil
}

// Performs the multiplication between a query vector and a value in the storage, then saves it in result.
// It receives task via the taskCh
func SpawnMultiplierBenchmark(evt bfv.Evaluator, ecd bfv.Encoder, params bfv.Parameters, taskCh chan multiplierTaskBenchmark) {
	for {
		task, ok := <-taskCh
		if !ok {
			//closed
			return
		}
		var values []rlwe.Operand
		var err error
		switch task.Values.(type) {
		case *PIREntry:
			values, err = task.Values.(*PIREntryBenchmark).Encode(settings.TUsableBits, ecd, params)
			if err != nil {
				panic(err.Error())
			}
		case []rlwe.Operand:
			values = task.Values.([]rlwe.Operand)
			break
		default:
			panic(fmt.Sprintf("Uknown type %T", task.Values))
		}
		intermediateResult := make([]*rlwe.Ciphertext, 0)
		for _, op := range values {
			el := evt.MulNew(task.Query, op)
			//if el.Degree() > 1 {
			//	evt.Relinearize(el, el)
			//}
			intermediateResult = append(intermediateResult, el)
		}
		//compress (accumulate result with lazy modswitch and relin) atomically
		task.ResultMap.Mux.Lock()
		if _, ok := task.ResultMap.Map[task.ResultKey]; !ok {
			task.ResultMap.Map[task.ResultKey] = make([]rlwe.Operand, 0)
		}
		result, _ := task.ResultMap.Map[task.ResultKey]
		for i := 0; i < int(utils.Min(float64(len(intermediateResult)), float64(len(result)))); i++ {
			evt.Add(result[i].(*rlwe.Ciphertext), intermediateResult[i], result[i].(*rlwe.Ciphertext))
		}
		if len(intermediateResult) > len(result) {
			//this result is longer then the one we had, add the additional ciphertexts
			newItemsIdx := len(result)
			for len(result) < len(intermediateResult) {
				result = append(result, intermediateResult[newItemsIdx])
				newItemsIdx++
			}
		}
		task.ResultMap.Map[task.ResultKey] = result
		task.ResultMap.Mux.Unlock()
		task.FeedBackCh <- 1
	}
}
