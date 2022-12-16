package pir

import (
	"errors"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
	utils2 "github.com/tuneinsight/lattigo/v4/utils"
	"log"
	"math"
	"math/rand"
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
	Items int
	Value [][]byte
	L     int
}

type PIREncodedEntry struct {
	Mux sync.RWMutex
	V   []rlwe.Operand
}

// Interface for an abstract storage type
type Storage interface {
	Load(key interface{}) (interface{}, bool)
}
type PIRStorage struct {
	Mux sync.RWMutex
	Map map[string][]rlwe.Operand
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
	v := make([]byte, PE.Items*PE.L+PE.Items-1)
	i := 0
	for _, b := range PE.Value {
		for _, byt := range b {
			v[i] = byt
			i++
		}
		if i < len(v) {
			v[i] = []byte("|")[0]
			i++
		}
	}
	return v
}

func (PE *PIREntry) Encode(t int, box settings.HeBox) ([]rlwe.Operand, error) {
	chunks, err := utils.Chunkify(PE.Coalesce(), t)
	if err != nil {
		return nil, err
	}
	return utils.EncodeChunks(chunks, box), nil
}

type PIRServer struct {
	Box      settings.HeBox
	Store    map[string]*PIREntry
	Db       map[string][]byte
	Profiles map[int]*settings.PIRProfile
}

func NewPirServer(db map[string][]byte) *PIRServer {
	PS := new(PIRServer)
	PS.Db = db
	return PS
}

func (PS *PIRServer) WithProfile(pf *settings.PIRProfile) error {
	//set up box from profile
	params, err := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN: pf.LogN,
		Q:    pf.Q,
		P:    pf.P,
		T:    settings.T,
	})
	if err != nil {
		return err
	}
	PS.Box = settings.HeBox{
		Params: params,
		Ecd:    bfv.NewEncoder(params),
		Evt: bfv.NewEvaluator(params, rlwe.EvaluationKey{
			Rlk:  pf.Rlk,
			Rtks: pf.Rtks,
		}),
	}
	return nil
}

func (PS *PIRServer) Add(key []byte, value []byte, dimentions, Kd, maxBinSize int) (int, error) {
	k, _ := utils.MapKeyToDim(key, Kd, dimentions)
	if e, ok := PS.Store[k]; ok {
		return e.Update(value, maxBinSize)
	} else {
		PS.Store[k] = NewPirEntry(value)
		return 1, nil
	}
}

func (PS *PIRServer) Modify(key []byte, value []byte, pos, dimentions, Kd int) error {
	k, _ := utils.MapKeyToDim(key, Kd, dimentions)
	if e, ok := PS.Store[k]; ok {
		return e.Modify(value, pos)
	} else {
		return errors.New("This key is new!")
	}
}

func (PS *PIRServer) Delete(key []byte, pos, Kd, dimentions int) error {
	k, _ := utils.MapKeyToDim(key, Kd, dimentions)
	if e, ok := PS.Store[k]; ok {
		return e.Delete(pos)
	} else {
		return errors.New("This key is new!")
	}
}

func (PS *PIRServer) Encode(ctx *settings.PirContext, K, Kd, Dimentions int, keySub []string) (*sync.Map, error) {
	PS.Store = make(map[string]*PIREntry)
	maxCollisions := 0
	l := 0
	for _, v := range PS.Db {
		l = len(v)
		break
	}

	for key, value := range PS.Db {
		if len(value) != l {
			return nil, errors.New(fmt.Sprintf("Not uniform byte length for records: Had %d and now %d", l, len(value)))
		}
		process := true
		if keySub != nil {
			if !utils.IsIn(keySub, key) {
				process = false
			}
		}
		if process {
			k, _ := utils.MapKeyToDim([]byte(key), Kd, Dimentions)
			if e, ok := PS.Store[k]; ok {
				//update
				collisions, err := e.Update(value, ctx.MaxBinSize)
				if err != nil {
					fmt.Errorf(err.Error())
				}
				if collisions+1 > maxCollisions {
					maxCollisions = collisions + 1
				}
			} else {
				//store new
				PS.Store[k] = NewPirEntry(value)
			}
		}
	}
	log.Println()
	fmt.Printf("		Storage encoded in chunks :\n		Max size of bucket registered = %d / Expected %d --> Max bucket capacity = %d\n		Tot Keys: %d\n", maxCollisions, ctx.ExpectedBinSize, ctx.MaxBinSize, K)

	ecdStore := new(sync.Map)
	var wg sync.WaitGroup
	pool := runtime.NumCPU()
	poolCh := make(chan struct{}, pool)
	errCh := make(chan error)
	//init pool chan
	for i := 0; i < pool; i++ {
		poolCh <- struct{}{}
	}
	for k, e := range PS.Store {
		<-poolCh //if no routines this is blocking
		go func(k string, e *PIREntry) {
			wg.Add(1)
			defer wg.Done()
			v, err := e.Encode(settings.TUsableBits, PS.Box)
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
		return nil, err
	default:
		//empty means no err
		return ecdStore, nil
	}
}

type multiplierTask struct {
	Query      *rlwe.Ciphertext
	Values     []rlwe.Operand //from db
	ResultMap  *PIRStorage    //map to save result of query x values
	ResultKey  string         //key of result map
	FeedBackCh chan int       //flag completion of one mul to caller
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

// Obliviously expands a compressed query vector. Queries must provided rotation keys
func (PS *PIRServer) ObliviousExpand(query []*rlwe.Ciphertext, rtKeys *rlwe.RotationKeySet, dimentions, Kd int) ([][]*rlwe.Ciphertext, error) {
	//Procedure 7 from https://eprint.iacr.org/2019/1483.pdf
	evt := rlwe.NewEvaluator(PS.Box.Params.Parameters, &rlwe.EvaluationKey{Rtks: rtKeys})
	if len(query) != dimentions {
		return nil, errors.New(fmt.Sprintf("Query vector has not the right size. Expected %d got %d", dimentions, len(query)))
	}
	logm := int(math.Ceil(math.Log2(float64(Kd))))
	if logm > PS.Box.Params.LogN() {
		return nil, errors.New("m > N is not allowed")
	}
	expanded := make([][]*rlwe.Ciphertext, dimentions)
	var err error
	var wg sync.WaitGroup
	for j := range query {
		wg.Add(1)
		go func(j int, evt *rlwe.Evaluator) {
			defer wg.Done()
			expanded[j] = invNTTforExpand(evt.Expand(query[j], logm, 0), Kd, PS.Box.Params.RingQ())
		}(j, evt.ShallowCopy())
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
func (PS *PIRServer) AnswerGen(ecdStore Storage, queryRecvd *PIRQuery, pp *settings.PIRProfile) ([]*rlwe.Ciphertext, error) {
	//Initialize sampler from user seed
	rand.Seed(queryRecvd.Seed)
	keyPRNG := make([]byte, 64)
	rand.Read(keyPRNG)
	prng, err := utils2.NewKeyedPRNG(keyPRNG)
	if err != nil {
		return nil, err
	}
	sampler := ringqp.NewUniformSampler(prng, *PS.Box.Params.RingQP())
	var query [][]*rlwe.Ciphertext
	switch queryRecvd.Q.(type) {
	case []*PIRQueryCt:
		var err error
		if pp.Rtks == nil {
			return nil, errors.New("Client needs to provide rotation keys for Expand")
		}
		queryDecompressed, err := DecompressCT(queryRecvd.Q, sampler, PS.Box.Params)
		query, err = PS.ObliviousExpand(queryDecompressed.([]*rlwe.Ciphertext), pp.Rtks, queryRecvd.Dimentions, queryRecvd.Kd)
		if err != nil {
			return nil, err
		}
	case [][]*PIRQueryCt:
		queryDecompressed, err := DecompressCT(queryRecvd.Q, sampler, PS.Box.Params)
		if err != nil {
			return nil, err
		}
		query = queryDecompressed.([][]*rlwe.Ciphertext)
	default:
		return nil, errors.New(fmt.Sprintf("Query must be []*rlwe.Ciphertext or [][]*rlwe.Ciphertext, not %T", query))
	}
	if pp.Rlk == nil {
		return nil, errors.New("Relinearization key for user is nil")
	}
	evt := bfv.NewEvaluator(PS.Box.Params, rlwe.EvaluationKey{Rlk: pp.Rlk})
	if queryRecvd.Kd != len(query[0]) {
		return nil, errors.New(fmt.Sprintf("queryExp vector has not the right size. Expected %d got %d", queryRecvd.Kd, len(query[0])))
	}
	if queryRecvd.Dimentions != len(query) {
		return nil, errors.New(fmt.Sprintf("Dimentionality mismatch. Expected %d got %d", queryRecvd.Dimentions, len(query)))
	}

	//spawnMultipliers
	taskCh := make(chan multiplierTask, runtime.NumCPU())

	var wg sync.WaitGroup //sync graceful termination
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			SpawnMultiplier(evt.ShallowCopy(), taskCh)
			defer wg.Done()
		}()
	}

	finalAnswer := make([]*rlwe.Ciphertext, 0)
	for d := 0; d < queryRecvd.Dimentions; d++ {
		//loop over all dimentions of the hypercube
		q := query[d]
		//the idea is to exploit the sync Map for encoding (concurrent writes to disjoint sets of keys)
		//and nextStore for atomic read->add->write
		nextStore := NewPirStorage()
		keys := make([]string, 0) //builds access to storage in a recursive way

		finalRound := d == queryRecvd.Dimentions-1

		utils.GenKeysAtDepth("", d+1, queryRecvd.Dimentions, queryRecvd.Kd, &keys)

		numEffectiveKeys := 0                                     //keeps track of how many entries are effectively in storage at a given dim
		numComputedKeys := 0                                      //keeps track of how many query x entry results have been computed in storage at a given dim
		feedbackCh := make(chan int, queryRecvd.Kd*(len(keys)+1)) //+1 for final round when len(keys) is 0

		for di := 0; di < queryRecvd.Kd; di++ {
			//scan this dimention

			if !finalRound {
				for _, k := range keys {
					nextK := k[1:] //remove "|"
					k = strconv.FormatInt(int64(di), 10) + k
					//feed multipliers
					if e, ok := ecdStore.Load(k); ok {
						numEffectiveKeys++
						//fmt.Printf("Level: %d x %d, depth: %d\n", q[di].Level(), e.([]rlwe.Operand)[0].Level(), d)
						taskCh <- multiplierTask{
							Query:      q[di],
							Values:     e.([]rlwe.Operand),
							ResultMap:  nextStore,
							ResultKey:  nextK,
							FeedBackCh: feedbackCh,
						}
					}
				}
			} else {
				k := strconv.FormatInt(int64(di), 10)
				if e, ok := ecdStore.Load(k); ok {
					numEffectiveKeys++
					taskCh <- multiplierTask{
						Query:      q[di],
						Values:     e.([]rlwe.Operand),
						ResultMap:  nextStore,
						ResultKey:  "",
						FeedBackCh: feedbackCh,
					}
				}
			}
			//wait for the routines to compute the keys for this di
		}
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
func SpawnMultiplier(evt bfv.Evaluator, taskCh chan multiplierTask) {
	for {
		task, ok := <-taskCh
		if !ok {
			//closed
			return
		}
		intermediateResult := make([]*rlwe.Ciphertext, 0)
		for _, op := range task.Values {
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
