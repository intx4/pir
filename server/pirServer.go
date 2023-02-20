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

var DEFAULTSIZE = 300 * 8
var DEFAULTSTARTITEMS = 1 << 10 //1024
var DEFAULTDIMS = 3
var DEFAULTN = 1 << 13

var ITEMSEPARATOR = []byte("|")

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

// This interface represents one element contained in the PIRDBEntry (e.g an ICFRecord)
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
	for i, v := range PE.Value {
		if !v.IsExpired() {
			newValue = append(newValue, v)
		} else {
			utils.Logger.WithFields(logrus.Fields{"service": "cache", "index": i}).Info("Removed element")
			removed++
		}
	}
	PE.Value = newValue
	PE.Items = len(newValue)
	return removed
}

func (PE *PIRDBEntry) coalesce() []byte {
	v := make([]byte, 0)
	i := 0
	for iv, val := range PE.Value {
		b := val.SuccinctEncode()
		for _, byt := range b {
			v = append(v, byt)
			i++
		}
		if iv != len(PE.Value)-1 {
			v = append(v, ITEMSEPARATOR...)
			i += len(ITEMSEPARATOR)
		}
	}
	return v
}

// Encodes entry as an array of RLWE ptx
func (PE *PIRDBEntry) EncodeRLWE(t int, ecd bfv.Encoder, params bfv.Parameters) ([]rlwe.Operand, error) {
	PE.Mux.Lock()
	defer PE.Mux.Unlock()
	chunks, err := utils.Chunkify(PE.coalesce(), t)
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

// Main DB Struct for storing data and caching
type PIRDBStorage struct {
	Mux     *sync.RWMutex //global lock: the philosophy is to allow selectively global atomic operations and concurrent access to the map
	Db      *sync.Map     //string -> PIRDBEntry
	Context *settings.PirContext
	Items   int //actual number of items
}

func NewPirDBStorage() (*PIRDBStorage, error) {
	ctx, err := settings.NewPirContext(DEFAULTSTARTITEMS, DEFAULTSIZE, DEFAULTN, DEFAULTDIMS)
	return &PIRDBStorage{
		Mux:     new(sync.RWMutex),
		Db:      new(sync.Map),
		Items:   0,
		Context: ctx,
	}, err
}

// Gets a copy of current context
func (S *PIRDBStorage) getContext() settings.PirContext {
	S.Mux.RLock()
	defer S.Mux.RUnlock()
	return *S.Context
}

// re-Encode S DB as hypercube according to context in a concurrent fashion
func (S *PIRDBStorage) reEncode() {
	ctx := S.Context
	Kd, dimentions := ctx.Kd, ctx.Dim

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
		<-poolCh
		wg.Add(1)
		go func(value *PIRDBEntry) {
			defer wg.Done()
			for _, item := range value.Value {
				record := item.(*ICFRecord)
				k, _ := utils.MapKeyToDim([]byte(record.Suci), Kd, dimentions)
				utils.Logger.WithFields(logrus.Fields{"suci": record.Suci, "key": k, "context": ctx.Hash()}).Debug("Reassigning entry in encode")
				v := NewPirDBEntry()
				v.Items = 1
				v.Value = append(v.Value, item)
				if e, load := ecdStorage.LoadOrStore(k, v); load {
					//merge atomically the two values
					e.(*PIRDBEntry).Mux.Lock()
					e.(*PIRDBEntry).Value = append(e.(*PIRDBEntry).Value, item)
					e.(*PIRDBEntry).Items += 1
					e.(*PIRDBEntry).Mux.Unlock()
				}
				k, _ = utils.MapKeyToDim([]byte(record.FiveGGUTI), Kd, dimentions)
				utils.Logger.WithFields(logrus.Fields{"guti": record.FiveGGUTI, "key": k, "context": ctx.Hash()}).Debug("Reassigning entry in encode")
				v = NewPirDBEntry()
				v.Items = 1
				v.Value = append(v.Value, item)
				if e, load := ecdStorage.LoadOrStore(k, v); load {
					//merge atomically the two values
					e.(*PIRDBEntry).Mux.Lock()
					e.(*PIRDBEntry).Value = append(e.(*PIRDBEntry).Value, item)
					e.(*PIRDBEntry).Items += 1
					e.(*PIRDBEntry).Mux.Unlock()
				}
			}
			poolCh <- struct{}{}
		}(value.(*PIRDBEntry))
		return true
	})
	wg.Wait()
	utils.Logger.WithFields(logrus.Fields{"service": "PIR", "context": S.Context.Hash()}).Info("Encoded DB")
	S.Db = ecdStorage
}

func (S *PIRDBStorage) Add(event *IEFRecord) {
	S.Mux.Lock() //needed to avoid insert during re-encoding
	defer S.Mux.Unlock()
	suci, guti := "", ""
	keyS, keyG := "", ""

	if event.Assoc != nil {
		suci = event.Assoc.Suci
	} else if event.DeAssoc != nil {
		suci = event.DeAssoc.Suci
	}
	if suci != "" {
		keyS, _ = utils.MapKeyToDim([]byte(suci), S.Context.Kd, S.Context.Dim)
	}
	//GUTI
	if event.Assoc != nil {
		guti = event.Assoc.FiveGGUTI
	} else if event.DeAssoc != nil {
		guti = event.DeAssoc.FiveGGUTI
	}
	if guti != "" {
		keyG, _ = utils.MapKeyToDim([]byte(guti), S.Context.Kd, S.Context.Dim)
	}
	if v, loaded := S.Db.Load(keyS); !loaded { //no nead for LoadOrStore as cache insertion is atomic
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "suci": suci, "key": keyS}).Info("Registering event in new entry in DB")
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "Dimentions": S.Context.Dim, "Kd": S.Context.Kd, "N": S.Context.N, "hash": S.Context.Hash()}).Debug("With Context")
		v = NewPirDBEntry()
		S.Items += v.(*PIRDBEntry).AddValue(event)
		S.Db.Store(keyS, v)
	} else {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "suci": suci, "key": keyS}).Info("Adding event in entry in DB")
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "Dimentions": S.Context.Dim, "Kd": S.Context.Kd, "N": S.Context.N, "hash": S.Context.Hash()}).Debug("With Context")
		S.Items += v.(*PIRDBEntry).AddValue(event)
	}
	if v, loaded := S.Db.Load(keyG); !loaded { //no nead for LoadOrStore as cache insertion is atomic
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "guti": guti, "key": keyG}).Info("Registering event in new entry in DB")
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "Dimentions": S.Context.Dim, "Kd": S.Context.Kd, "N": S.Context.N, "hash": S.Context.Hash()}).Debug("With Context")
		v = NewPirDBEntry()
		S.Items += v.(*PIRDBEntry).AddValue(event)
		S.Db.Store(keyG, v)
	} else {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "guti": guti, "key": keyG}).Info("Adding event in entry in DB")
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "Dimentions": S.Context.Dim, "Kd": S.Context.Kd, "N": S.Context.N, "hash": S.Context.Hash()}).Debug("With Context")
		S.Items += v.(*PIRDBEntry).AddValue(event)
	}
	S.checkContext()
}

type PIRServer struct {
	Profiles   map[string]map[string]*settings.PIRProfileSet //ctxHash -> client id -> profiles
	Storage    *PIRDBStorage
	RecordChan chan *IEFRecord
}

func NewPirServer(recordChan chan *IEFRecord) (*PIRServer, error) {
	PS := new(PIRServer)
	var err error
	PS.Storage, err = NewPirDBStorage()
	PS.Profiles = make(map[string]map[string]*settings.PIRProfileSet)
	PS.RecordChan = recordChan
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
		utils.Logger.WithFields(logrus.Fields{"service": "PIR"}).Info("Caching new event")
		PS.Storage.Add(event)
	}
}

// Checks the current state of the DB and updates the context, if needed
func (S *PIRDBStorage) checkContext() {
	var err error
	utils.Logger.WithFields(logrus.Fields{"service": "PIR", "contextHash": S.Context.Hash(), "actual items": S.Items, "configured items": S.Context.Items}).Info("Checking context")
	if S.Context.Items <= S.Items {
		//bigger context needed
		n := DEFAULTN
		if S.Items > 1<<20 {
			n = 1 << 14
		}
		S.Context, err = settings.NewPirContext(S.Items*2, DEFAULTSIZE, n, DEFAULTDIMS)
		if err != nil {
			utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Info("Error while enlarging DB")
			panic(err)
		}
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "contextHash": S.Context.Hash()}).Info("Changing to bigger DB representation")
		S.reEncode()
	} else if S.Context.Items > 2*S.Items {
		n := DEFAULTN
		if S.Items > 1<<20 {
			n = 1 << 14
		}
		S.Context, err = settings.NewPirContext(S.Items, DEFAULTSIZE, n, DEFAULTDIMS)
		if err != nil {
			utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Info("Error while shrinking DB")
			panic(err)
		}
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "contextHash": S.Context.Hash()}).Info("Changing to smaller DB representation")
		S.reEncode()
	}
}

// Worker which periodically sweaps the cache
func (S *PIRDBStorage) Sweaper() {
	for true {
		utils.Logger.WithFields(logrus.Fields{"service": "cache", "ttl(s)": CACHETTL}).Info("Starting sweaping routine")
		S.Mux.Lock()
		S.Db.Range(func(key, value any) bool {
			utils.Logger.WithFields(logrus.Fields{"service": "cache", "key": key}).Info("Sweaping Entry")
			S.Items -= value.(*PIRDBEntry).Sweap()
			return true
		})
		S.Mux.Unlock()
		time.Sleep(time.Duration(CACHETTL) * time.Second)
	}
}

func (S *PIRDBStorage) Load(key interface{}) (interface{}, bool) {
	v, ok := S.Db.Load(key.(string))
	return v, ok
}

// Save keys from profile of pb. Caller should verify the consistency of the context in which the profile was generated
func (PS *PIRServer) AddProfile(clientId string, leakage int, pf *settings.PIRProfile) {
	ctx := PS.Storage.getContext()
	utils.Logger.WithFields(logrus.Fields{"service": "PIR", "contextHash": ctx.Hash(), "clientId": clientId, "leakage": leakage}).Info("Adding profile")
	if _, ok := PS.Profiles[ctx.Hash()]; !ok {
		PS.Profiles[ctx.Hash()] = make(map[string]*settings.PIRProfileSet)
	}
	if pf != nil {
		if _, ok := PS.Profiles[ctx.Hash()][clientId]; !ok {
			PS.Profiles[ctx.Hash()][clientId] = settings.NewProfileSet()
		}
		PS.Profiles[ctx.Hash()][clientId].P[leakage] = pf
	}
	utils.Logger.WithFields(logrus.Fields{"service": "PIR", "contextHash": ctx.Hash(), "clientId": clientId, "leakage": leakage}).Info("Profile Added")
}

func (PS *PIRServer) GetContext() *settings.PirContext {
	ctx := new(settings.PirContext)
	*ctx = PS.Storage.getContext()
	return ctx
}

// Set up an HE box from clientID (fetch keys) and params
func (PS *PIRServer) WithParams(clientId string, leakage int) (*settings.HeBox, error) {
	//set up box from profile
	box := new(settings.HeBox)
	ctx := PS.Storage.getContext()
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
func (S *PIRDBStorage) obliviousExpand(query []interface{}, box *settings.HeBox) ([][]*rlwe.Ciphertext, error) {
	//Procedure 7 from https://eprint.iacr.org/2019/1483.pdf
	Kd := S.Context.Kd
	evt := rlwe.NewEvaluator(box.Params.Parameters, &rlwe.EvaluationKey{Rtks: box.Rtks})
	logm := int(math.Ceil(math.Log2(float64(Kd))))
	if logm > box.Params.LogN() {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": "Dimention > N not allowed"}).Error("ObliviousExpand")
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
				utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": fmt.Sprintf("Unknown type in %T", query[j])}).Error("ObliviousExpand")
				err = errors.New(fmt.Sprintf("Unknown type in %T", query[j]))
			}
		}(j, evt)
	}
	wg.Wait()
	return expanded, err
}

// Takes a PIRQuery, Returns an array of interfaces, where each element is either a []*rlwe.Ciphertext or an int that represents the index for that dimention
func (S *PIRDBStorage) processPIRQuery(queryRecvd *messages.PIRQuery, box *settings.HeBox) ([][]*rlwe.Ciphertext, error) {
	var query [][]*rlwe.Ciphertext
	//Initialize sampler from user seed
	sampler, err := messages.NewSampler(queryRecvd.Seed, box.Params)
	if err != nil {
		return nil, err
	}

	if queryRecvd.Q.Compressed != nil {
		var err error
		if box.Rtks == nil {
			utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": "Client needs to provide rtks"}).Error("processPIRQuery")
			return nil, errors.New("Client needs to provide rotation keys for Expand")
		}
		queryDecompressed, err := messages.DecompressCT(queryRecvd.Q.Compressed, *sampler, box.Params)
		query, err = S.obliviousExpand(queryDecompressed, box)
		if err != nil {
			return nil, err
		}
	} else if queryRecvd.Q.Expanded != nil {
		queryDecompressed, err := messages.DecompressCT(queryRecvd.Q.Expanded, *sampler, box.Params)
		if err != nil {
			return nil, err
		}
		for _, qd := range queryDecompressed {
			query = append(query, qd.([]*rlwe.Ciphertext))
		}
	} else {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": "Bad container"}).Error("processPIRQuery")
		return nil, errors.New("Bad container")
	}
	return query, nil
}

// Message for concurrent multiplication algorithm
type multiplierTask struct {
	Query      *rlwe.Ciphertext
	Values     interface{} //from db
	ResultMap  *sync.Map   //map to save result of query x values
	ResultKey  string      //key of result map
	FeedBackCh chan int    //flag completion of one mul to caller
}

/*
Given a query in the form (prefix, ciphers) answers.
The query can be represented as:
  - a prefix, as a series of key coords ("C0|C1..." or ""), depending on the information leakage
  - a series of d ciphertexts. In this case the query goes through an oblivious expansion procedure that generates the same query as case 1
    For every bucket (which consists of N (ring size of BFV) entries, with 1 or more data items), it multiplies the bucket
    with the associated ciphertext in the query.
    After that, all these results get accumulated by summing the results.
    Returns a list of ciphertexts, i.e the answer, which is the result of the accumulation
    between all buckets in the server multiplied by the query. Ideally only one element in a certain bucket will survive
    the selection. The resulting bucket is returned to the client which can decrypt the answer and retrieve the value
*/
func (S *PIRDBStorage) answerGen(box *settings.HeBox, prefix string, query [][]*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	ecdStore := S.Db
	Kd, Dimentions := S.Context.Kd, S.Context.Dim
	evt := bfv.NewEvaluator(box.Params, rlwe.EvaluationKey{Rlk: box.Rlk})
	ecd := bfv.NewEncoder(box.Params)
	skippedDims := 0
	for _, s := range strings.Split(prefix, "|") {
		if s != "" {
			skippedDims++
		}
	}

	if Kd != len(query[len(query)-1]) {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": fmt.Sprintf("queryExp vector has not the right size. Expected %d got %d", Kd, len(query[len(query)-1]))}).Error("answerGen")
		return nil, errors.New(fmt.Sprintf("queryExp vector has not the right size. Expected %d got %d", Kd, len(query[len(query)-1])))
	}
	if Dimentions != len(query)+skippedDims {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": fmt.Sprintf("Dimentionality mismatch. Expected %d got %d", Dimentions, len(query)+skippedDims)}).Error("answerGen")
		return nil, errors.New(fmt.Sprintf("Dimentionality mismatch. Expected %d got %d", Dimentions, len(query)+skippedDims))
	}
	var wg sync.WaitGroup //sync graceful termination
	//filter dimentions
	if prefix != "" {
		keys := make([]string, 0)
		utils.GenKeysAtDepth(prefix, skippedDims, Dimentions, Kd, &keys)
		tmpStorage := new(sync.Map)
		filterChan := make(chan struct{}, runtime.NumCPU())
		for i := 0; i < runtime.NumCPU(); i++ {
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
	}

	//spawnMultipliers
	taskCh := make(chan multiplierTask, runtime.NumCPU()) //runtime.NumCPU()

	for i := 0; i < runtime.NumCPU(); i++ { //runtime.NumCPU()
		wg.Add(1)
		go func() {
			defer wg.Done()
			spawnMultiplier(evt.ShallowCopy(), ecd.ShallowCopy(), box.Params, taskCh)
		}()
	}

	finalAnswer := make([]*rlwe.Ciphertext, 0)
	var err error
	for d := 0; d < len(query); d++ {
		//loop over all dimentions of the hypercube

		//fmt.Println("dimention ", d+1)
		q := query[d]

		nextStore := new(sync.Map)
		//builds access to storage in a recursive way
		keys := make([]string, 0)
		utils.GenKeysAtDepth("", d+skippedDims+1, Dimentions, Kd, &keys)

		finalRound := d == len(query)-1

		numEffectiveKeys := 0                          //keeps track of how many entries are effectively in storage at a given dim
		numComputedKeys := 0                           //keeps track of how many query x entry results have been computed in storage at a given dim
		feedbackCh := make(chan int, Kd*(len(keys)+1)) //+1 for final round when len(keys) is 0
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
		if err != nil {
			return nil, err
		}
		//relin and modswitch + recursively update storage
		ecdStore = new(sync.Map)
		nextStore.Range(func(key, value any) bool {
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
		if finalRound {
			break
		}
	}
	close(taskCh)
	wg.Wait()
	return finalAnswer, err
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
			//if el.Degree() > 1 {
			//	evt.Relinearize(el, el)
			//}
			intermediateResult = append(intermediateResult, el)
		}
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
					result = append(result.(*PIREntry).Ops, intermediateResult[newItemsIdx])
					newItemsIdx++
				}
			}
			result.(*PIREntry).Mux.Unlock()
		}
		task.FeedBackCh <- 1
	}
}

// Process and answer a query coming from the pb
func (S *PIRDBStorage) Answer(query *messages.PIRQuery, box *settings.HeBox) ([]*rlwe.Ciphertext, error) {
	S.Mux.RLock()
	defer S.Mux.RUnlock()
	utils.Logger.WithFields(logrus.Fields{"service": "PIR", "Dimentions": S.Context.Dim, "Kd": S.Context.Kd, "N": S.Context.N, "hash": S.Context.Hash()}).Debug("With Context")
	start := time.Now()
	queryProc, err := S.processPIRQuery(query, box)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Error("Answer")
		return nil, err
	}
	answer, err := S.answerGen(box, query.Prefix, queryProc)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Error("Answer")
	}
	end := time.Since(start)
	utils.Logger.WithFields(logrus.Fields{"service": "PIR", "time": end}).Info("Answered PIR Query")
	return answer, err
}

func (PS *PIRServer) Answer(query *messages.PIRQuery) ([]*rlwe.Ciphertext, error) {
	box, err := PS.WithParams(query.ClientId, query.Leakage)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "PIR", "error": err.Error()}).Error("Answer")
		return nil, err
	}
	utils.Logger.WithFields(logrus.Fields{"service": "PIR", "clientId": query.ClientId, "leakage": query.Leakage}).Info("Answering query")
	return PS.Storage.Answer(query, box)
}

// Starts the caching daemon of PIR DB
func (PS *PIRServer) Start() {
	PS.cache()
}
