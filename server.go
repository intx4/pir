package pir

import (
	"errors"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"log"
	"math"
	"pir/settings"
	"pir/utils"
	"runtime"
	"strconv"
	"sync"
)

/*
Record of the PIR Database in bytes. It contains a value (that is a sequence of bytes, representing 1 or more data items)
*/
type PIREntry struct {
	Items int      `json:"items,omitempty"`
	Value [][]byte `json:"value,omitempty"`
	L     int      `json:"l,omitempty"`
}

// Interface for an abstract storage type
type Storage interface {
	Load(key interface{}) (interface{}, bool)
}
type PIRStorage struct {
	Mux sync.RWMutex
	Map map[string][]rlwe.Operand `json:"map,omitempty"`
}

func NewPirStorage() *PIRStorage {
	storage := new(PIRStorage)
	storage.Mux = sync.RWMutex{}
	storage.Map = make(map[string][]rlwe.Operand)
	return storage
}

func (S *PIRStorage) Load(key interface{}) (interface{}, bool) {
	S.Mux.RLock()
	defer S.Mux.RUnlock()
	v, ok := S.Map[key.(string)]
	return v, ok
}

func NewPirEntry(value []byte) *PIREntry {
	return &PIREntry{Items: 1, Value: [][]byte{value}, L: len(value)}
}

func (PE *PIREntry) Update(newValue []byte, maxBinSize int) (int, error) {
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

func (PE *PIREntry) Modify(newValue []byte, pos int) error {
	if len(newValue) != PE.L {
		return errors.New(fmt.Sprintf("Byte length of data stored in this entry is not uniform. Old %d, new %d", PE.L, len(newValue)))
	}
	if pos > len(PE.Value) || pos < 0 {
		return errors.New(fmt.Sprintf("Invalid position for update: %d/%d", pos, PE.Items))
	}
	PE.Value[pos] = newValue
	return nil
}

func (PE *PIREntry) Delete(pos int) error {
	if pos > PE.Items || pos < 0 {
		return errors.New(fmt.Sprintf("Invalid position for update: %d/%d", pos, PE.Items))
	}
	PE.Value = append(PE.Value[:pos], PE.Value[pos+1:]...)
	PE.Items--
	return nil
}

func (PE *PIREntry) Coalesce() []byte {
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

func (PE *PIREntry) Encode(t int, ecd bfv.Encoder, params bfv.Parameters) ([]rlwe.Operand, error) {
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

type PIRServer struct {
	Store    *sync.Map
	Profiles map[string]*settings.PIRProfile
}

func NewPirServer() *PIRServer {
	PS := new(PIRServer)
	PS.Store = new(sync.Map)
	PS.Profiles = make(map[string]*settings.PIRProfile)
	return PS
}

func (PS *PIRServer) Add(key []byte, value []byte, dimentions, Kd, maxBinSize int) (int, error) {
	k, _ := utils.MapKeyToDim(key, Kd, dimentions)
	if e, ok := PS.Store.Load(k); ok {
		return e.(*PIREntry).Update(value, maxBinSize)
	} else {
		PS.Store.Store(k, NewPirEntry(value))
		return 1, nil
	}
}

func (PS *PIRServer) Modify(key []byte, value []byte, pos, dimentions, Kd int) error {
	k, _ := utils.MapKeyToDim(key, Kd, dimentions)
	if e, ok := PS.Store.Load(k); ok {
		return e.(*PIREntry).Modify(value, pos)
	} else {
		return errors.New("This key is new!")
	}
}

func (PS *PIRServer) Delete(key []byte, pos, Kd, dimentions int) error {
	k, _ := utils.MapKeyToDim(key, Kd, dimentions)
	if e, ok := PS.Store.Load(k); ok {
		return e.(*PIREntry).Delete(pos)
	} else {
		return errors.New("This key is new!")
	}
}

func (PS *PIRServer) AddProfile(pf *settings.PIRProfile) {
	PS.Profiles[pf.ClientId] = pf
}
func (PS *PIRServer) WithParams(clientId, paramsId string) (*settings.HeBox, error) {
	//set up box from profile
	box := new(settings.HeBox)
	for _, p := range PS.Profiles[clientId].CryptoParams {
		if p.ParamsId == paramsId {
			params, err := bfv.NewParametersFromLiteral(p.Params)
			if err != nil {
				return nil, err
			}
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
		}
	}
	return box, nil
}

// Takes a PIRQuery, Returns an array of interfaces, where each element is either a []*rlwe.Ciphertext or an int that represents the index for that dimention
func (PS *PIRServer) ProcessPIRQuery(queryRecvd *PIRQuery, box *settings.HeBox) ([]interface{}, error) {
	var query []interface{} //each entry is either an array of ciphertexts or directly the index to retrieve for this dimention for WPIR
	//Initialize sampler from user seed
	sampler, err := NewSampler(queryRecvd.Seed, box.Params)
	if err != nil {
		return nil, err
	}

	switch queryRecvd.Q.(type) {
	case []*PIRQueryItem:
		var err error
		if box.Rtks == nil {
			return nil, errors.New("Client needs to provide rotation keys for Expand")
		}
		queryDecompressed, err := DecompressCT(queryRecvd.Q, *sampler, box.Params)
		query, err = PS.ObliviousExpand(queryDecompressed, box, queryRecvd.Dimentions, queryRecvd.Kd)
		if err != nil {
			return nil, err
		}
	case [][]*PIRQueryItem:
		queryDecompressed, err := DecompressCT(queryRecvd.Q, *sampler, box.Params)
		if err != nil {
			return nil, err
		}
		query = queryDecompressed
	default:
		return nil, errors.New(fmt.Sprintf("Query must be []*rlwe.Ciphertext or [][]*rlwe.Ciphertext, not %T", query))
	}
	return query, nil
}

func (PS *PIRServer) Encode(K, Kd, dimentions int, ctx *settings.PirContext, box *settings.HeBox, query []interface{}, db map[string][]byte) (*sync.Map, error) {
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
			if e, ok := PS.Store.LoadOrStore(key, NewPirEntry(value)); ok {
				//update
				collisions, err := e.(*PIREntry).Update(value, ctx.MaxBinSize)
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
	fmt.Printf("		Storage encoded in chunks :\n		Max size of bucket registered = %d / Expected %d --> Max bucket capacity = %d\n		Tot Keys: %d\n", maxCollisions, ctx.ExpectedBinSize, ctx.MaxBinSize, K)
	/*
		ecdStore := new(sync.Map)

		for k, e := range PS.Store {
			<-poolCh //if no routines this is blocking
			wg.Add(1)
			go func(k string, e *PIREntry) {
				defer wg.Done()
				v, err := e.Encode(settings.TUsableBits, box.Ecd.ShallowCopy(), box.Params)
				if err != nil {
					errCh <- err
				}
				//cast to operands
				//fmt.Printf("Encoding level %d\n", v[0].Level())
				ecdStore.Store(k, v)
				poolCh <- struct{}{} //restore 1 routine
			}(k, e)
		}
		wg.Wait()
		select {
		case err := <-errCh:
			return nil, nil, err
		default:
			//empty means no err
			return ecdStore, box, nil
		}

	*/
	ecdStorage := new(sync.Map)
	*ecdStorage = *PS.Store
	return ecdStorage, nil
}

type multiplierTask struct {
	Query      *rlwe.Ciphertext
	Values     interface{} //from db
	ResultMap  *PIRStorage //map to save result of query x values
	ResultKey  string      //key of result map
	FeedBackCh chan int    //flag completion of one mul to caller
}

// puts back from NTT domain the ciphertexts and returns expandedCts[:t]
func invNTTforExpand(expandedCts []*rlwe.Ciphertext, t int, Q *ring.Ring) []*rlwe.Ciphertext {
	for _, expCt := range expandedCts[:t] {
		for _, ci := range expCt.Value {
			Q.InvNTTLvl(expCt.Level(), ci, ci)
		}
		expCt.IsNTT = false
	}
	return expandedCts[:t]
}

// Obliviously expands a compressed query vector. Client must provide rotation keys. Returns an array of interfaces, where each element is either a []*rlwe.Ciphertext or an int that represents the index for that dimention
func (PS *PIRServer) ObliviousExpand(query []interface{}, box *settings.HeBox, dimentions, Kd int) ([]interface{}, error) {
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

/*
Given an encoded PIR database and a query from client, answers the query.
The query can be represented as:
  - a series query vectors of ciphertexts. In each vector (we have d vectors for d dimentions), each ciphertext is Enc(0), but for one
    where ct is Enc(1). If this ct is the ct in position i-th, then you will retrieve all associated to index i for this dimention
  - a series of d ciphertexts. In this case the query goes through an oblivious expansion procedure that generates the same query as case 1
    For every bucket (which consists of N (ring size of BFV) entries, with 1 or more data items), it multiplies the bucket
    with the associated ciphertext in the query.
    After that, all these results get accumulated by summing the results.
    Returns a list of ciphertexts, i.e the answer, which is the result of the accumulation
    between all buckets in the server multiplied by the query. Ideally only one element in a certain bucket will survive
    the selection. The resulting bucket is returned to the client which can decrypt the answer and retrieve the value
*/
func (PS *PIRServer) AnswerGen(ecdStore Storage, box *settings.HeBox, query []interface{}, K, Kd, Dimentions int) ([]*rlwe.Ciphertext, error) {
	evt := bfv.NewEvaluator(box.Params, rlwe.EvaluationKey{Rlk: box.Rlk})
	ecd := bfv.NewEncoder(box.Params)
	if Kd != len(query[len(query)-1].([]*rlwe.Ciphertext)) {
		return nil, errors.New(fmt.Sprintf("queryExp vector has not the right size. Expected %d got %d", Kd, len(query[len(query)-1].([]*rlwe.Ciphertext))))
	}
	if Dimentions != len(query) {
		return nil, errors.New(fmt.Sprintf("Dimentionality mismatch. Expected %d got %d", Dimentions, len(query)))
	}

	//spawnMultipliers
	taskCh := make(chan multiplierTask, runtime.NumCPU())
	var wg sync.WaitGroup //sync graceful termination
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			SpawnMultiplier(evt.ShallowCopy(), ecd.ShallowCopy(), box.Params, taskCh)
		}()
	}

	finalAnswer := make([]*rlwe.Ciphertext, 0)
	for d := 0; d < Dimentions; d++ {
		//loop over all dimentions of the hypercube

		//fmt.Println("dimention ", d+1)
		q := query[d]

		//the idea is to exploit the sync Map for encoding (concurrent writes to disjoint sets of keys)
		//and nextStore for atomic read->add->write
		nextStore := NewPirStorage()
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
						taskCh <- multiplierTask{
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
						case *PIREntry:
							nextStore.Map[key], err = v.(*PIREntry).Encode(settings.TUsableBits, ecd.ShallowCopy(), box.Params)
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
		ecdStore = NewPirStorage() //we transform ecdStore into a PIRStorage after first iter to reduce memory
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
				ecdStore.(*PIRStorage).Map[key] = value
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
func SpawnMultiplier(evt bfv.Evaluator, ecd bfv.Encoder, params bfv.Parameters, taskCh chan multiplierTask) {
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
			values, err = task.Values.(*PIREntry).Encode(settings.TUsableBits, ecd, params)
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
