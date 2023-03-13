package server

import (
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"log"
	"math"
	"pir/messages"
	"pir/settings"
	"pir/utils"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var DEFAULTDIMS = 3
var ITEMSEPARATOR = []byte("|")
var CPUS = runtime.NumCPU()

type PIRDBEntry struct {
	Items int      `json:"items,omitempty"`
	Value [][]byte `json:"value,omitempty"`
	L     int      `json:"l,omitempty"`
}

func NewPirDBEntry(value []byte) *PIRDBEntry {
	return &PIRDBEntry{Items: 1, Value: [][]byte{value}, L: len(value)}
}

func (PE *PIRDBEntry) Update(newValue []byte, maxBinSize int) (int, error) {
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

func (PE *PIRDBEntry) Coalesce() []byte {
	v := make([]byte, len(PE.Value)*PE.L+len(PE.Value)-1)
	i := 0
	for iv, b := range PE.Value {
		for _, byt := range b {
			v[i] = byt
			i++
		}
		if iv != len(PE.Value)-1 {
			v = append(v, ITEMSEPARATOR...)
			i += len(ITEMSEPARATOR)
		}
	}
	return v
}

func (PE *PIRDBEntry) EncodeRLWE(t int, ecd bfv.Encoder, params bfv.Parameters) ([]rlwe.Operand, error) {
	chunks, err := utils.Chunkify(PE.Coalesce(), t)
	if err != nil {
		return nil, err
	}
	ecdChunks := utils.EncodeChunks(chunks, ecd, params)
	//if len(ecdChunks) > 1 {
	//	log.Println("Bin contains > 1 plaintexts")
	//}
	return ecdChunks, nil
}

// Entry of PIRStorage struct
// Leverages concurrent access of sync.Map while deferring atomicity to internal lock
// Used during computation
type PIREntry struct {
	Mux *sync.RWMutex
	Ops []rlwe.Operand
}

func NewPirEntry() *PIREntry {
	return &PIREntry{
		Mux: new(sync.RWMutex),
		Ops: make([]rlwe.Operand, 0),
	}
}

type PIRServer struct {
	Store    *sync.Map
	Profiles map[string]map[string]*settings.PIRProfileSet //ctxHash -> client id -> profiles
	Context  *settings.PirContext
}

func NewPirServer(ctx *settings.PirContext, db [][]byte) (*PIRServer, error) {
	PS := new(PIRServer)
	PS.Profiles = make(map[string]map[string]*settings.PIRProfileSet)
	K, Kd := ctx.K, ctx.Kd

	//pad
	for len(db) < K*ctx.MaxBinSize {
		b := make([]byte, len(db[0])/8)
		for i := 0; i < len(b); i++ {
			b[i] = []byte("A")[0]
		}
		db = append(db, b)
	}

	ecdStorage := new(sync.Map)
	for dbIdx := 0; dbIdx < len(db)/ctx.MaxBinSize; dbIdx++ {
		bin := db[dbIdx*ctx.MaxBinSize : dbIdx*ctx.MaxBinSize+ctx.MaxBinSize]
		hcIdx, _ := utils.Decompose(dbIdx, Kd, ctx.Dim)
		for _, b := range bin {
			if entry, loaded := ecdStorage.LoadOrStore(hcIdx, NewPirDBEntry(b)); loaded {
				entry.(*PIRDBEntry).Update(b, ctx.MaxBinSize)
			}
		}
	}

	PS.Store = ecdStorage
	PS.Context = ctx
	return PS, nil
}

func (PS *PIRServer) AddProfile(clientId string, leakage int, pf *settings.PIRProfile) {
	ctx := PS.Context
	if _, ok := PS.Profiles[ctx.Hash()]; !ok {
		PS.Profiles[ctx.Hash()] = make(map[string]*settings.PIRProfileSet)
	}
	if pf != nil {
		if pf.Rtks != nil && pf.Rlk != nil {
			if _, ok := PS.Profiles[ctx.Hash()][clientId]; !ok {
				PS.Profiles[ctx.Hash()][clientId] = settings.NewProfileSet()
			}
			PS.Profiles[ctx.Hash()][clientId].P[leakage] = pf
			utils.Logger.WithFields(logrus.Fields{"service": "PIR", "contextHash": ctx.Hash(), "clientId": clientId, "leakage": leakage}).Info("Profile Added")
		} else {
			utils.Logger.WithFields(logrus.Fields{"service": "PIR", "contextHash": ctx.Hash(), "clientId": clientId, "leakage": leakage}).Warn("Skipping profile as no keys are contained")
		}
	}
}

// set up box from profile
func (PS *PIRServer) WithParams(clientId string, leakage int) (*settings.HeBox, error) {
	box := new(settings.HeBox)
	ctx := PS.Context
	utils.Logger.WithFields(logrus.Fields{"service": "PIR", "contextHash": ctx.Hash(), "clientId": clientId, "leakage": leakage}).Info("Fetching profile")
	if p, ok := PS.Profiles[ctx.Hash()][clientId]; !ok {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": fmt.Sprintf("profile not found %s for creating HEBOX", clientId)}).Error("Error")
		return nil, errors.New(fmt.Sprintf("%s profile not found", clientId))
	} else {
		//take set of params from client profiles according to leakage
		params, err := bfv.NewParametersFromLiteral(settings.PARAMS[p.P[leakage].ParamsId])
		if err != nil {
			return nil, err
		}
		box = &settings.HeBox{
			Params: params,
			Ecd:    bfv.NewEncoder(params),
			Evt: bfv.NewEvaluator(params, rlwe.EvaluationKey{
				Rlk:  p.P[leakage].Rlk,
				Rtks: p.P[leakage].Rtks,
			}),
			Rtks: p.P[leakage].Rtks,
			Rlk:  p.P[leakage].Rlk,
		}
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "contextHash": ctx.Hash(), "clientId": clientId, "leakage": leakage}).Info("Profile found, created HEBox")
		return box, nil
	}
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

// Obliviously expands a compressed query vector. Client must provide rotation keys. Returns an array of []*rlwe.Ciphertext
func (PS *PIRServer) ObliviousExpand(query []interface{}, box *settings.HeBox, dimentions, Kd int) ([][]*rlwe.Ciphertext, error) {
	//Procedure 7 from https://eprint.iacr.org/2019/1483.pdf
	evt := rlwe.NewEvaluator(box.Params.Parameters, &rlwe.EvaluationKey{Rtks: box.Rtks})
	logm := int(math.Ceil(math.Log2(float64(Kd))))
	if logm > box.Params.LogN() {
		return nil, errors.New("m > N is not allowed")
	}
	expanded := make([][]*rlwe.Ciphertext, len(query))
	var err error
	var wg sync.WaitGroup
	for j := range query {
		wg.Add(1)
		go func(j int, evt *rlwe.Evaluator) {
			defer wg.Done()
			switch query[j].(type) {
			case *rlwe.Ciphertext:
				expanded[j] = invNTTforExpand(evt.ShallowCopy().Expand(query[j].(*rlwe.Ciphertext), logm, 0), Kd, box.Params.RingQ())
			default:
				panic(fmt.Sprintf("Unknown type in %T", query[j]))
			}
		}(j, evt)
	}
	wg.Wait()
	return expanded, err
}

// Takes a PIRQuery, Returns an array of interfaces, where each element is either a []*rlwe.Ciphertext or an int that represents the index for that dimention
func (PS *PIRServer) ProcessPIRQuery(ctx *settings.PirContext, queryRecvd *messages.PIRQuery, box *settings.HeBox) ([][]*rlwe.Ciphertext, error) {
	var query [][]*rlwe.Ciphertext
	//Initialize sampler from user seed
	sampler, err := messages.NewSampler(queryRecvd.Seed, box.Params)
	if err != nil {
		return nil, err
	}

	if queryRecvd.Q.Compressed != nil {
		var err error
		if box.Rtks == nil {
			return nil, errors.New("Client needs to provide rotation keys for Expand")
		}
		start := time.Now()
		queryDecompressed, err := messages.DecompressCT(queryRecvd.Q.Compressed, *sampler, box.Params)
		query, err = PS.ObliviousExpand(queryDecompressed, box, ctx.Dim, ctx.Kd)
		if err != nil {
			return nil, err
		}
		end := time.Since(start)
		fmt.Println("	Decompress + expand time: ", end.Seconds())
	} else if queryRecvd.Q.Expanded != nil {
		queryDecompressed, err := messages.DecompressCT(queryRecvd.Q.Expanded, *sampler, box.Params)
		if err != nil {
			return nil, err
		}
		for _, qd := range queryDecompressed {
			query = append(query, qd.([]*rlwe.Ciphertext))
		}
	} else {
		return nil, errors.New("Bad container")
	}
	return query, nil
}

func (PS *PIRServer) Encode(ctx *settings.PirContext, db map[string][]byte) (*sync.Map, error) {
	K, Kd, dimentions := ctx.K, ctx.Kd, ctx.Dim
	maxCollisions := 0
	l := 0
	for _, v := range db {
		l = len(v)
		break
	}
	tooBigErr := ""

	ecdStorage := new(sync.Map)
	var wg sync.WaitGroup
	pool := CPUS
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
		k, _ := utils.MapKeyToDim([]byte(key), Kd, dimentions)
		<-poolCh
		wg.Add(1)
		go func(key string, value []byte) {
			defer wg.Done()
			if e, ok := ecdStorage.LoadOrStore(key, NewPirDBEntry(value)); ok {
				//update
				collisions, err := e.(*PIRDBEntry).Update(value, ctx.MaxBinSize)
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

	return ecdStorage, nil
}

type multiplierTask struct {
	Query      *rlwe.Ciphertext
	Values     interface{} //from db
	ResultMap  *sync.Map   //map to save result of query x values
	ResultKey  string      //key of result map
	FeedBackCh chan int    //flag completion of one mul to caller
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
func (PS *PIRServer) AnswerGen(ecdStore *sync.Map, box *settings.HeBox, prefix string, query [][]*rlwe.Ciphertext, ctx *settings.PirContext) ([]*rlwe.Ciphertext, error) {
	Kd, Dimentions := ctx.Kd, ctx.Dim
	evt := bfv.NewEvaluator(box.Params, rlwe.EvaluationKey{Rlk: box.Rlk})
	ecd := bfv.NewEncoder(box.Params)
	skippedDims := 0
	for _, s := range strings.Split(prefix, "|") {
		if s != "" {
			skippedDims++
		}
	}
	if Kd != len(query[len(query)-1]) {
		return nil, errors.New(fmt.Sprintf("queryExp vector has not the right size. Expected %d got %d", Kd, len(query[len(query)-1])))
	}
	if Dimentions != len(query)+skippedDims {
		return nil, errors.New(fmt.Sprintf("Dimentionality mismatch. Expected %d got %d", Dimentions, len(query)+skippedDims))
	}

	var wg sync.WaitGroup //sync graceful termination
	//filter dimentions

	if prefix != "" {
		start := time.Now()
		keys := make([]string, 0)
		utils.GenKeysAtDepth(prefix, skippedDims, Dimentions, Kd, &keys)
		tmpStorage := new(sync.Map)
		filterChan := make(chan struct{}, CPUS)
		for i := 0; i < CPUS; i++ {
			filterChan <- struct{}{}
		}
		for _, key := range keys {
			wg.Add(1)
			<-filterChan
			go func(k string) {
				defer wg.Done()
				if v, ok := ecdStore.Load(k); ok {
					nextk := strings.TrimPrefix(k, prefix+"|")
					tmpStorage.Store(nextk, v)
				}
				filterChan <- struct{}{}
			}(key)
		}
		wg.Wait()
		ecdStore = tmpStorage
		end := time.Since(start)
		fmt.Println("	Dimentions filtering: ", end.Seconds())
	}

	//spawnMultipliers
	taskCh := make(chan multiplierTask, CPUS)

	for i := 0; i < CPUS; i++ { //runtime.NumCPU()
		wg.Add(1)
		go func() {
			defer wg.Done()
			spawnMultiplier(evt.ShallowCopy(), ecd.ShallowCopy(), box.Params, taskCh)
		}()
	}

	finalAnswer := make([]*rlwe.Ciphertext, 0)
	start := time.Now()
	for d := 0; d < len(query); d++ {
		//loop over all dimentions of the hypercube
		q := query[d]

		nextStore := new(sync.Map)
		//builds access to storage in a recursive way
		keys := make([]string, 0)
		utils.GenKeysAtDepth("", d+skippedDims+1, Dimentions, Kd, &keys)

		finalRound := d == len(query)-1

		numEffectiveKeys := 0                          //keeps track of how many entries are effectively in storage at a given dim
		numComputedKeys := 0                           //keeps track of how many query x entry results have been computed in storage at a given dim
		feedbackCh := make(chan int, Kd*(len(keys)+1)) //+1 for final round when len(keys) is 0

		//fmt.Printf("Dimention %d performing mul\n", d+1)
		for di := 0; di < Kd; di++ {
			//scan this dimention
			//fmt.Println("Index: ", di)
			//utils.ShowCoeffs(q[di], *box)
			for _, k := range keys {
				nextK := ""
				//build key of storage
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
						Query:      q[di],
						Values:     e,
						ResultMap:  nextStore,
						ResultKey:  nextK,
						FeedBackCh: feedbackCh,
					}
				}
			}
		}

		//wait for the routines to compute the keys for this di
		for numComputedKeys < numEffectiveKeys {
			numComputedKeys += <-feedbackCh
		}

		ecdStore = new(sync.Map) //we transform ecdStore into a PIRStorage after first iter to reduce memory
		nextStore.Range(func(key, value any) bool {
			for _, ct := range value.(*PIREntry).Ops {
				//if d != 0 && ct.Degree() > 1 {
				//	//after first we have done a ct x pt -> deg is still 1
				//	evt.Relinearize(ct.(*rlwe.Ciphertext), ct.(*rlwe.Ciphertext))
				//}
				if finalRound && key == "" {
					for ct.(*rlwe.Ciphertext).Level() != 0 {
						evt.Rescale(ct.(*rlwe.Ciphertext), ct.(*rlwe.Ciphertext))
					}
					finalAnswer = append(finalAnswer, ct.(*rlwe.Ciphertext))
				}
			}
			if !finalRound {
				ecdStore.Store(key, &PIREntry{
					Mux: new(sync.RWMutex),
					Ops: value.(*PIREntry).Ops,
				})
				return true
			} else if key == "" {
				return false
			}
			return true
		})
	}
	close(taskCh)
	wg.Wait()
	end := time.Since(start)
	fmt.Println("	Answering time: ", end.Seconds())
	return finalAnswer, nil
}

// Performs the multiplication between a query vector and a value in the storage, then saves it in result.
// It receives task via the taskCh
func spawnMultiplier(evt bfv.Evaluator, ecd bfv.Encoder, params bfv.Parameters, taskCh chan multiplierTask) {
	for {
		task, ok := <-taskCh
		if !ok {
			//closed
			return
		}
		var values []rlwe.Operand
		var err error
		switch task.Values.(type) {
		case *PIRDBEntry:
			values, err = task.Values.(*PIRDBEntry).EncodeRLWE(settings.TUsableBits, ecd, params)
			if err != nil {
				utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Error("spawnMultiplier")
				task.FeedBackCh <- 1
			}
		case *PIREntry:
			values = task.Values.(*PIREntry).Ops
			break
		default:
			utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": fmt.Sprintf("Uknown type %T", task.Values)}).Error("spawnMultiplier")
			task.FeedBackCh <- 1
		}
		intermediateResult := make([]rlwe.Operand, 0)
		for _, op := range values {
			el := evt.MulNew(task.Query, op)
			if el.Degree() > 1 {
				evt.Relinearize(el, el)
			}
			intermediateResult = append(intermediateResult, el)
		}
		//compress (accumulate result with lazy modswitch and relin) atomically
		if result, loaded := task.ResultMap.LoadOrStore(
			task.ResultKey, &PIREntry{Mux: new(sync.RWMutex), Ops: intermediateResult}); loaded {
			result.(*PIREntry).Mux.Lock()
			for i := 0; i < int(utils.Min(float64(len(intermediateResult)), float64(len(result.(*PIREntry).Ops)))); i++ {
				evt.Add(result.(*PIREntry).Ops[i].(*rlwe.Ciphertext), intermediateResult[i], result.(*PIREntry).Ops[i].(*rlwe.Ciphertext))
			}
			if len(intermediateResult) > len(result.(*PIREntry).Ops) {
				//this result is longer then the one we had, add the additional ciphertexts
				newItemsIdx := len(result.(*PIREntry).Ops)
				for len(result.(*PIREntry).Ops) < len(intermediateResult) {
					result.(*PIREntry).Ops = append(result.(*PIREntry).Ops, intermediateResult[newItemsIdx])
					newItemsIdx++
				}
			}
			result.(*PIREntry).Mux.Unlock()
		}
		task.FeedBackCh <- 1
	}
}

func (PS *PIRServer) Answer(query *messages.PIRQuery) (*messages.PIRAnswer, error) {
	if query.Profile != nil {
		if PS.Context.Hash() == query.Profile.ContextHash {
			//add profile and then generate crypto material from it
			PS.AddProfile(query.ClientId, query.Leakage, query.Profile)
			box, err := PS.WithParams(query.ClientId, query.Leakage)
			if err != nil {
				return nil, err
			}
			start := time.Now()
			queryProc, err := PS.ProcessPIRQuery(PS.Context, query, box)
			if err != nil {
				utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Error("Answer")
				return nil, err
			}
			answer, err := PS.AnswerGen(PS.Store, box, query.Prefix, queryProc, PS.Context)
			if err != nil {
				utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Error("Answer")
			}
			end := time.Since(start)
			utils.Logger.WithFields(logrus.Fields{"service": "PIR", "time": end}).Info("Answered PIR Query")
			return &messages.PIRAnswer{
				FetchContext: false,
				Answer:       answer,
				Context:      PS.Context,
				Error:        "",
				Ok:           true,
			}, nil
		} else {
			return nil, errors.New(settings.ContextError)
		}
	} else if query.FetchContext {
		return &messages.PIRAnswer{
			FetchContext: true,
			Answer:       nil,
			Context:      PS.Context,
			Error:        "",
			Ok:           true,
		}, nil
	} else {
		return nil, errors.New(settings.MissingProfileError)
	}
	return nil, errors.New("No profile nor fetch context request in query")
}
