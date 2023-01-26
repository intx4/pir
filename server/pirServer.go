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
	"pir"
	"pir/settings"
	"pir/utils"
	"runtime"
	"strconv"
	"sync"
	"time"
)

var DEFAULTSIZE = 300 * 8
var DEFAULTSTARTITEMS = 1 << 16
var DEFAULTDIMS = 3
var DEFAULTN = 1 << 13

// this interface represents one element contained in the PIREntry
type pirDBItem interface {
	SuccinctEncode() []byte
	SuccinctDecode([]byte) error
	Match(interface{}) bool
	IsExpired() bool
}

/*
Record of the PIR Database in bytes. It contains a value (that is a sequence of bytes, representing 1 or more data items)
*/
type PIRDBEntry struct {
	Items int           `json:"items,omitempty"`
	Value []pirDBItem   `json:"value,omitempty"`
	Mux   *sync.RWMutex //for atomic add or remove
}

func NewPirDBEntry() *PIRDBEntry {
	return &PIRDBEntry{Items: 0, Value: []pirDBItem{}, Mux: new(sync.RWMutex)}
}

// Adds a new event from IEF
func (PE *PIRDBEntry) AddValue(record *IEFRecord) int {
	PE.Mux.Lock()
	defer PE.Mux.Unlock()
	added := 0
	if record.Assoc != nil {
		PE.Value = append(PE.Value, &ICFRecord{
			Supi:          record.Assoc.Supi,
			FiveGGUTI:     record.Assoc.FiveGGUTI,
			StartTimestmp: record.Assoc.Timestmp,
			Suci:          record.Assoc.Suci,
			MaxTTL:        time.Now(),
		})
		added = 1
	} else if record.DeAssoc != nil {
		for _, v := range PE.Value {
			if v.Match(record.DeAssoc) {
				v.(*ICFRecord).EndTimestpm = record.DeAssoc.Timestmp
				v.(*ICFRecord).CacheTTL = time.Now()
			}
		}
	}
	PE.Items = len(PE.Value)
	return added
}

// Sweaps entry looking for expired entries
func (PE *PIRDBEntry) Sweap() int {
	PE.Mux.Lock()
	defer PE.Mux.Unlock()
	removed := 0
	newValue := make([]pirDBItem, 0)
	for _, v := range PE.Value {
		if !v.IsExpired() {
			newValue = append(newValue, v)
		} else {
			removed++
		}
	}
	PE.Value = newValue
	PE.Items = len(newValue)
	return removed
}

func (PE *PIRDBEntry) Coalesce() []byte {
	v := make([]byte, 0)
	i := 0
	for iv, val := range PE.Value {
		b := val.SuccinctEncode()
		for _, byt := range b {
			v = append(v, byt)
			i++
		}
		if iv != len(PE.Value)-1 {
			v[i] = []byte("|")[0]
			i++
		}
	}
	return v
}

// Encodes entry as an array of RLWE ptx
func (PE *PIRDBEntry) EncodeRLWE(t int, ecd bfv.Encoder, params bfv.Parameters) ([]rlwe.Operand, error) {
	chunks, err := utils.Chunkify(PE.Coalesce(), t)
	if err != nil {
		return nil, err
	}
	ecdChunks := utils.EncodeChunks(chunks, ecd, params)
	if len(ecdChunks) > 1 {
		log.Println("Bin contains > 1 plaintexts")
		utils.Logger.WithFields(logrus.Fields{"service": "PIR"}).Warn("PIR bin contains > 1 plaintexts")
	}
	return ecdChunks, nil
}

// Interface for an abstract storage type, either PIRStorage (map with global lock) or sync.Map
type Storage interface {
	Load(key interface{}) (interface{}, bool)
}

//type PIRStorage struct {
//	Mux sync.RWMutex
//	Map map[string][]rlwe.Operand `json:"map,omitempty"`
//}

type PIRDBStorage struct {
	Mux           *sync.RWMutex //global lock: the phylosophy is to allow selectively global atomic operations and concurrent access to the map
	Db            *sync.Map     //string -> pirdbentry
	Context       *settings.PirContext
	EncodedBySUCI bool //GUTI or SUCI
	Items         int
}

func NewPirDBStorage(encodedBySUCI bool) (*PIRDBStorage, error) {
	ctx, err := settings.NewPirContext(DEFAULTSTARTITEMS, DEFAULTSIZE, DEFAULTN, DEFAULTDIMS)
	return &PIRDBStorage{
		Mux:           new(sync.RWMutex),
		Db:            new(sync.Map),
		EncodedBySUCI: encodedBySUCI,
		Items:         0,
		Context:       ctx,
	}, err
}

// Gets a copy of current context
func (S *PIRDBStorage) getContext() settings.PirContext {
	S.Mux.RLock()
	defer S.Mux.RUnlock()
	return *S.Context
}

// Encode S DB as hypercube according to context in a concurrent fashion
func (S *PIRDBStorage) encode() {
	ctx := S.Context
	_, Kd, dimentions := ctx.K, ctx.Kd, ctx.Dim

	ecdStorage := new(sync.Map)
	var wg sync.WaitGroup
	pool := runtime.NumCPU()
	poolCh := make(chan struct{}, pool)
	//errCh := make(chan error)
	//init pool chan
	for i := 0; i < pool; i++ {
		poolCh <- struct{}{}
	}
	S.Db.Range(func(key, value any) bool {
		k, _ := utils.MapKeyToDim([]byte(key.(string)), Kd, dimentions)
		<-poolCh
		wg.Add(1)
		go func(key string, value *PIRDBEntry) {
			defer wg.Done()
			if e, load := ecdStorage.LoadOrStore(key, value); load {
				//merge atomically the two values
				e.(*PIRDBEntry).Mux.Lock()
				value.Mux.Lock()
				e.(*PIRDBEntry).Value = append(e.(*PIRDBEntry).Value, value.Value...)
				value.Mux.Unlock()
				e.(*PIRDBEntry).Mux.Unlock()
			}
			poolCh <- struct{}{}
		}(k, value.(*PIRDBEntry))
		return true
	})
	wg.Wait()
	utils.Logger.WithFields(logrus.Fields{"service": "PIR", "context": S.Context}).Info("Encoded DB")
	S.Db = ecdStorage
}

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

// PIRStorage is used during computation.
// Supports concurrent lockups while atomicity is defered to single entry level
type PIRStorage struct {
	Map *sync.Map `json:"map,omitempty"` //string -> PIREntry
}

func NewPirStorage() *PIRStorage {
	storage := new(PIRStorage)
	storage.Map = new(sync.Map)
	return storage
}

// Deprecated
func (S *PIRDBStorage) EncodeRLWE(params bfv.Parameters) *PIRStorage {
	S.Mux.Unlock()
	defer S.Mux.Unlock()
	ctx := S.Context
	ecd := bfv.NewEncoder(params)
	_, Kd, dimentions := ctx.K, ctx.Kd, ctx.Dim

	ecdStorage := new(sync.Map)
	var wg sync.WaitGroup
	pool := runtime.NumCPU()
	poolCh := make(chan struct{}, pool)
	//errCh := make(chan error)
	//init pool chan
	for i := 0; i < pool; i++ {
		poolCh <- struct{}{}
	}
	S.Db.Range(func(key, value any) bool {
		k, _ := utils.MapKeyToDim([]byte(key.(string)), Kd, dimentions)
		<-poolCh
		wg.Add(1)
		go func(key string, value *PIRDBEntry) {
			defer wg.Done()
			ops, err := value.EncodeRLWE(settings.TUsableBits, ecd.ShallowCopy(), params)
			entry := NewPirEntry()
			entry.Ops = ops
			ecdStorage.Store(key, entry)
			if err != nil {
				panic(err)
			}
			ecdStorage.Store(k, NewPirEntry())
			poolCh <- struct{}{}
		}(k, value.(*PIRDBEntry))
		return true
	})
	wg.Wait()
	return &PIRStorage{Map: ecdStorage}
}

func (S *PIRStorage) Load(key interface{}) (interface{}, bool) {
	v, ok := S.Load(key.(string))
	return v, ok
}

func (S *PIRDBStorage) Add(event *IEFRecord) {
	S.Mux.Lock() //needed to avoid insert during re-encoding
	defer S.Mux.Unlock()
	key, _ := "", []int{}
	if S.EncodedBySUCI {
		suci := ""
		if event.Assoc != nil {
			suci = event.Assoc.Suci
		} else if event.DeAssoc != nil {
			suci = event.DeAssoc.Suci
		}
		key, _ = utils.MapKeyToDim([]byte(suci), S.Context.Kd, S.Context.Dim)
	} else {
		//GUTI
		guti := ""
		if event.Assoc != nil {
			guti = event.Assoc.FiveGGUTI
		} else if event.DeAssoc != nil {
			guti = event.DeAssoc.FiveGGUTI
		}
		key, _ = utils.MapKeyToDim([]byte(guti), S.Context.Kd, S.Context.Dim)
	}
	if v, loaded := S.Db.Load(key); !loaded { //no nead for LoadOrStore as cache insertion is atomic
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "key": key}).Info("Registering event in new entry in DB")
		v = NewPirDBEntry()
		S.Items += v.(*PIRDBEntry).AddValue(event)
		S.Db.Store(key, v)
	} else {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "key": key}).Info("Adding event to entry in DB")
		S.Items += v.(*PIRDBEntry).AddValue(event)
	}
	S.checkContext()
}

type PIRServer struct {
	Profiles   map[string]*settings.PIRProfile
	Storage    *PIRDBStorage
	RecordChan chan *IEFRecord
	Params     bfv.Parameters
}

func NewPirServer(recordChan chan *IEFRecord, params bfv.Parameters) (*PIRServer, error) {
	PS := new(PIRServer)
	var err error
	PS.Storage, err = NewPirDBStorage(true)
	PS.Profiles = make(map[string]*settings.PIRProfile)
	PS.RecordChan = recordChan
	PS.Params = params
	return PS, err
}

// Listen and cache new IEF events
func (PS *PIRServer) cache() {
	go func() {
		//sweaper routine
		PS.Storage.Sweaper()
	}()
	for true {
		event := <-PS.RecordChan
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "event": event}).Info("Caching event")
		PS.Storage.Add(event)
	}
}

// Checks the current state of the DB and updates the context, if needed
func (S *PIRDBStorage) checkContext() {
	var err error
	if S.Context.Items <= S.Items {
		//bigger context needed
		S.Context, err = settings.NewPirContext(S.Items*2, DEFAULTSIZE, DEFAULTN, DEFAULTDIMS)
		if err != nil {
			utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Info("Error while enlarging DB")
			panic(err)
		}
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "context": S.Context}).Info("Changing to bigger DB representation")
		S.encode()
	} else if S.Items >= 3*S.Items {
		S.Context, err = settings.NewPirContext(S.Items*2, DEFAULTSIZE, DEFAULTN, DEFAULTDIMS)
		if err != nil {
			utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Info("Error while shrinking DB")
			panic(err)
		}
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "context": S.Context}).Info("Changing to smaller DB representation")
		S.encode()
	}
}

// Worker which periodically sweaps the cache
func (S *PIRDBStorage) Sweaper() {
	for true {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR"}).Info("Starting sweaping routine")
		S.Mux.Lock()
		S.Db.Range(func(key, value any) bool {
			S.Items -= value.(*PIRDBEntry).Sweap()
			return true
		})
		S.Mux.Unlock()
		time.Sleep(time.Duration(CACHETTL))
	}
}

func (S *PIRDBStorage) Load(key interface{}) (interface{}, bool) {
	v, ok := S.Load(key.(string))
	return v, ok
}

// Save keys from profile of client. Caller should verify the consistency of the context in which the profile was generated
func (PS *PIRServer) AddProfile(clientId string, pf *settings.PIRProfile) {
	if pf.Rlk != nil && pf.Rtks != nil {
		PS.Profiles[clientId] = &settings.PIRProfile{Rtks: pf.Rtks, Rlk: pf.Rlk} //store only keys
	}
}

func (PS *PIRServer) GetContext() *settings.PirContext {
	ctx := new(settings.PirContext)
	*ctx = PS.Storage.getContext()
	return ctx
}

func (PS *PIRServer) GetParams() bfv.ParametersLiteral {
	PS.Storage.Mux.RLock()
	defer PS.Storage.Mux.RUnlock()
	return PS.Params.ParametersLiteral()
}

// Set up an HE box from clientID (fetch keys) and params
func (PS *PIRServer) WithParams(params bfv.Parameters, clientId string) (*settings.HeBox, error) {
	//set up box from profile
	box := new(settings.HeBox)
	if p, ok := PS.Profiles[clientId]; !ok {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": fmt.Sprintf("profile not found %s for creating HEBOX", clientId)}).Error("Error")
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
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "clientID": clientId}).Info("Created HEBOX")
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

// Obliviously expands a compressed query vector. Client must provide rotation keys. Returns an array of interfaces, where each element is either a []*rlwe.Ciphertext or an int that represents the index for that dimention
func (S *PIRDBStorage) obliviousExpand(query []interface{}, box *settings.HeBox) ([]interface{}, error) {
	//Procedure 7 from https://eprint.iacr.org/2019/1483.pdf
	Kd, dimentions := S.Context.Kd, S.Context.Dim
	evt := rlwe.NewEvaluator(box.Params.Parameters, &rlwe.EvaluationKey{Rtks: box.Rtks})
	if len(query) != dimentions {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": fmt.Sprintf("Query vector has not the right size. Expected %d got %d", dimentions, len(query))}).Error("ObliviousExpand")
		return nil, errors.New(fmt.Sprintf("Query vector has not the right size. Expected %d got %d", dimentions, len(query)))
	}
	logm := int(math.Ceil(math.Log2(float64(Kd))))
	if logm > box.Params.LogN() {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": "Dimention > N not allowed"}).Error("ObliviousExpand")
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
				utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": fmt.Sprintf("Unknown type in %T", query[j])}).Error("ObliviousExpand")
				err = errors.New(fmt.Sprintf("Unknown type in %T", query[j]))
			}
		}(j, evt)
	}
	wg.Wait()
	return expanded, err
}

// Takes a PIRQuery, Returns an array of interfaces, where each element is either a []*rlwe.Ciphertext or an int that represents the index for that dimention
func (S *PIRDBStorage) processPIRQuery(queryRecvd *pir.PIRQuery, box *settings.HeBox) ([]interface{}, error) {
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
			utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": "Client needs to provide rtks"}).Error("processPIRQuery")
			return nil, errors.New("Client needs to provide rotation keys for Expand")
		}
		queryDecompressed, err := pir.DecompressCT(queryRecvd.Q, *sampler, box.Params)
		query, err = S.obliviousExpand(queryDecompressed, box)
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
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": fmt.Sprintf("Query must be []*rlwe.Ciphertext or [][]*rlwe.Ciphertext, not %T", query)}).Error("processPIRQuery")

		return nil, errors.New(fmt.Sprintf("Query must be []*rlwe.Ciphertext or [][]*rlwe.Ciphertext, not %T", query))
	}
	return query, nil
}

type multiplierTask struct {
	Query      *rlwe.Ciphertext
	Values     interface{} //from db
	ResultMap  *PIRStorage //map to save result of query x values
	ResultKey  string      //key of result map
	FeedBackCh chan int    //flag completion of one mul to caller
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
func (S *PIRDBStorage) answerGen(box *settings.HeBox, query []interface{}) ([]*rlwe.Ciphertext, error) {
	var ecdStore Storage
	ecdStore = S
	Kd, Dimentions := S.Context.Kd, S.Context.Dim
	evt := bfv.NewEvaluator(box.Params, rlwe.EvaluationKey{Rlk: box.Rlk})
	ecd := bfv.NewEncoder(box.Params)
	if Kd != len(query[len(query)-1].([]*rlwe.Ciphertext)) {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": fmt.Sprintf("queryExp vector has not the right size. Expected %d got %d", Kd, len(query[len(query)-1].([]*rlwe.Ciphertext)))}).Error("answerGen")
		return nil, errors.New(fmt.Sprintf("queryExp vector has not the right size. Expected %d got %d", Kd, len(query[len(query)-1].([]*rlwe.Ciphertext))))
	}
	if Dimentions != len(query) {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": fmt.Sprintf("Dimentionality mismatch. Expected %d got %d", Dimentions, len(query))}).Error("answerGen")

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
	var err error
	for d := 0; d < Dimentions; d++ {
		//loop over all dimentions of the hypercube

		//fmt.Println("dimention ", d+1)
		q := query[d]

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
						switch v.(type) {
						case *PIRDBEntry:
							v.(*PIRDBEntry).Mux.RLock()
							ops, err := v.(*PIRDBEntry).EncodeRLWE(settings.TUsableBits, ecd.ShallowCopy(), box.Params)
							v.(*PIRDBEntry).Mux.RUnlock()
							if err != nil {
								panic(err)
							}
							entry := NewPirEntry()
							entry.Ops = ops
							nextStore.Map.Store(key, entry)
						case *PIREntry:
							entry := NewPirEntry()
							v.(*PIREntry).Mux.RLock()
							entry.Ops = v.(*PIREntry).Ops
							v.(*PIREntry).Mux.RUnlock()
							nextStore.Map.Store(key, v.(*PIREntry))
						default:
							utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": fmt.Sprintf("Unknown type %T", v)}).Error("answerGen")
							err = errors.New(fmt.Sprintf("Unknown type %T", v))
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
		if err != nil {
			return nil, err
		}
		//relin and modswitch + recursively update storage
		ecdStore = NewPirStorage() //we transform ecdStore into a PIRStorage after first iter to reduce memory
		nextStore.Map.Range(func(key, value any) bool {
			for _, ct := range value.(*PIREntry).Ops {
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
				ecdStore.(*PIRStorage).Map.Store(key, &PIREntry{
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
	return finalAnswer, err
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
		intermediateResult := make([]*rlwe.Ciphertext, 0)
		for _, op := range values {
			el := evt.MulNew(task.Query, op)
			//if el.Degree() > 1 {
			//	evt.Relinearize(el, el)
			//}
			intermediateResult = append(intermediateResult, el)
		}
		//compress (accumulate result with lazy modswitch and relin) atomically
		if result, loaded := task.ResultMap.Map.LoadOrStore(task.ResultKey, intermediateResult); loaded {
			result.(*PIREntry).Mux.Lock()
			for i := 0; i < int(utils.Min(float64(len(intermediateResult)), float64(len(result.(*PIREntry).Ops)))); i++ {
				evt.Add(result.(*PIREntry).Ops[i].(*rlwe.Ciphertext), intermediateResult[i], result.(*PIREntry).Ops[i].(*rlwe.Ciphertext))
			}
			if len(intermediateResult) > len(result.(*PIREntry).Ops) {
				//this result is longer then the one we had, add the additional ciphertexts
				newItemsIdx := len(result.(*PIREntry).Ops)
				for len(result.(*PIREntry).Ops) < len(intermediateResult) {
					result = append(result.(*PIREntry).Ops, intermediateResult[newItemsIdx])
					newItemsIdx++
				}
			}
			result.(*PIREntry).Mux.Unlock()
		}
		task.FeedBackCh <- 1
	}
}
func (S *PIRDBStorage) Answer(query *pir.PIRQuery, box *settings.HeBox) ([]*rlwe.Ciphertext, error) {
	S.Mux.RLock()
	defer S.Mux.RUnlock()
	start := time.Now()
	queryProc, err := S.processPIRQuery(query, box)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Error("Answer")
		return nil, err
	}
	answer, err := S.answerGen(box, queryProc)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Error("Answer")
	}
	end := time.Since(start)
	utils.Logger.WithFields(logrus.Fields{"service": "PIR", "time": end}).Info("Answered PIR Query")
	return answer, err
}

func (PS *PIRServer) Answer(query *pir.PIRQuery) ([]*rlwe.Ciphertext, error) {
	box, err := PS.WithParams(PS.Params, query.ClientId)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Error("Answer")
		return nil, err
	}
	return PS.Storage.Answer(query, box)
}

func (PS *PIRServer) Start() {
	go func() {
		PS.cache()
	}()
}
