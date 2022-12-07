package pir

import (
	"errors"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"log"
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
	Context settings.PirContext
	Box     settings.HeBox
	Store   map[string]*PIREntry
}

func NewPirServer(c settings.PirContext, b settings.HeBox, keys [][]byte, values [][]byte) (*PIRServer, error) {
	PS := new(PIRServer)
	PS.Context = c
	PS.Box = b
	PS.Store = make(map[string]*PIREntry)

	maxCollisions := 0
	for i := 0; i < len(keys); i++ {
		if len(values[i]) != len(values[0]) {
			return nil, errors.New(fmt.Sprintf("Not uniform byte length for records: Had %d and now %d", len(values[0]), len(values[i])))
		}
		k, _ := utils.MapKeyToIdx(keys[i], c.Kd, c.Dimentions)
		if e, ok := PS.Store[k]; ok {
			//update
			collisions, err := e.Update(values[i], c.MaxBinSize)
			if err != nil {
				fmt.Errorf(err.Error())
			}
			if collisions+1 > maxCollisions {
				maxCollisions = collisions + 1
			}
		} else {
			//store new
			PS.Store[k] = NewPirEntry(values[i])
		}
	}
	log.Printf("	Storage encoded in chunks :\n		Max size of bucket registered = %d / Expected %d --> Max bucket capacity = %d\n		Tot Keys: %d\n", maxCollisions, PS.Context.ExpectedBinSize, PS.Context.MaxBinSize, PS.Context.K)
	return PS, nil
}

func (PS *PIRServer) Add(key []byte, value []byte) (int, error) {
	k, _ := utils.MapKeyToIdx(key, PS.Context.Kd, PS.Context.Dimentions)
	if e, ok := PS.Store[k]; ok {
		return e.Update(value, PS.Context.MaxBinSize)
	} else {
		PS.Store[k] = NewPirEntry(value)
		return 1, nil
	}
}

func (PS *PIRServer) Modify(key []byte, value []byte, pos int) error {
	k, _ := utils.MapKeyToIdx(key, PS.Context.Kd, PS.Context.Dimentions)
	if e, ok := PS.Store[k]; ok {
		return e.Modify(value, pos)
	} else {
		return errors.New("This key is new!")
	}
}

func (PS *PIRServer) Delete(key []byte, pos int) error {
	k, _ := utils.MapKeyToIdx(key, PS.Context.Kd, PS.Context.Dimentions)
	if e, ok := PS.Store[k]; ok {
		return e.Delete(pos)
	} else {
		return errors.New("This key is new!")
	}
}

func (PS *PIRServer) LoadRelinKey(rlk *rlwe.RelinearizationKey) {
	PS.Box.WithEvaluator(bfv.NewEvaluator(PS.Box.Params, rlwe.EvaluationKey{Rlk: rlk}))
}

func (PS *PIRServer) Encode() (*sync.Map, error) {
	ecdStore := new(sync.Map)
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
			v, err := e.Encode(PS.Context.TUsable, PS.Box)
			if err != nil {
				errCh <- err
			}
			//cast to operands
			//fmt.Printf("Encoding level %d\n", v[0].Level())
			ecdStore.Store(k, v)
			poolCh <- struct{}{} //restore 1 routine
		}(k, e)
	}
	select {
	case err := <-errCh:
		return nil, err
	default:
		//empty means no err
		return ecdStore, nil
	}
}

// Recursive function to generate keys at depth nextdepth = currdepth+1 (depth is a dimention)
func (PS *PIRServer) genKeysAtDepth(di string, nextDepth int, keys *[]string) {
	if nextDepth == PS.Context.Dimentions {
		*keys = append(*keys, di)
	} else {
		for dj := 0; dj < PS.Context.Kd; dj++ {
			PS.genKeysAtDepth(di+"|"+strconv.FormatInt(int64(dj), 10), nextDepth+1, keys)
		}
	}
}

type MultiplierTask struct {
	Query      *rlwe.Ciphertext
	Values     []rlwe.Operand //from db
	ResultMap  *PIRStorage    //map to save result of query x values
	ResultKey  string         //key of result map
	FeedBackCh chan int       //flag completion of one mul to caller
}

/*
Given an encoded PIR database and a query from client, answers the query.

	The query is represented as a series of ciphertext where every ciphertexts in Enc(0), but for one
	where one of the N slots is set to 1 to select the associated index in the db.
	For every bucket (which consists of N (ring size of BFV) entries, with 1 or more data items), it multiplies the bucket
	with the associated ciphertext in the query.
	After that, all these results get accumulated by summing the results.
	Returns a list of ciphertexts, i.e the answer, which is the result of the accumulation
	between all buckets in the server multiplied by the query. Ideally only one element in a certain bucket will survive
	the selection. The resulting bucket is returned to the client which can decrypt the answer and retrieve the value
*/
func (PS *PIRServer) AnswerGen(ecdStore Storage, query [][]*rlwe.Ciphertext, rlk *rlwe.RelinearizationKey) ([]*rlwe.Ciphertext, error) {
	evt := bfv.NewEvaluator(PS.Box.Params, rlwe.EvaluationKey{Rlk: rlk})
	if PS.Context.Kd != len(query[0]) {
		return nil, errors.New(fmt.Sprintf("Query vector has not the right size. Expected %d got %d", PS.Context.Kd, len(query[0])))
	}
	if PS.Context.Dimentions != len(query) {
		return nil, errors.New(fmt.Sprintf("Dimentionality mismatch. Expected %d got %d", PS.Context.Dimentions, len(query)))
	}

	//spawnMultipliers
	taskCh := make(chan MultiplierTask, runtime.NumCPU())

	var wg sync.WaitGroup //sync graceful termination
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			SpawnMultiplier(evt.ShallowCopy(), taskCh)
			defer wg.Done()
		}()
	}

	finalAnswer := make([]*rlwe.Ciphertext, 0)
	for d := 0; d < PS.Context.Dimentions; d++ {
		//loop over all dimentions of the hypercube
		q := query[d]
		//the idea is to exploit the sync Map for encoding (concurrent writes to disjoint sets of keys)
		//and nextStore for atomic read->add->write
		nextStore := NewPirStorage()
		keys := make([]string, 0) //builds access to storage in a recursive way

		finalRound := d == PS.Context.Dimentions-1

		PS.genKeysAtDepth("", d+1, &keys)

		numEffectiveKeys := 0                                     //keeps track of how many entries are effectively in storage at a given dim
		numComputedKeys := 0                                      //keeps track of how many query x entry results have been computed in storage at a given dim
		feedbackCh := make(chan int, PS.Context.Kd*(len(keys)+1)) //+1 for final round when len(keys) is 0

		for di := 0; di < PS.Context.Kd; di++ {
			//scan this dimention

			if !finalRound {
				for _, k := range keys {
					nextK := k[1:] //remove "|"
					k = strconv.FormatInt(int64(di), 10) + k
					//feed multipliers
					if e, ok := ecdStore.Load(k); ok {
						numEffectiveKeys++
						//fmt.Printf("Level: %d x %d, depth: %d\n", q[di].Level(), e.([]rlwe.Operand)[0].Level(), d)
						taskCh <- MultiplierTask{
							Query:      q[di],
							Values:     e.([]rlwe.Operand),
							ResultMap:  nextStore,
							ResultKey:  nextK,
							FeedBackCh: feedbackCh,
						}
					}
				}
			} else {
				//nextStore.LoadOrStore("", make([]rlwe.Operand, 0))
				k := strconv.FormatInt(int64(di), 10)
				if e, ok := ecdStore.Load(k); ok {
					numEffectiveKeys++
					taskCh <- MultiplierTask{
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
				if d != 0 {
					//after first we have done a ct x pt -> deg is still 1
					evt.Relinearize(ct.(*rlwe.Ciphertext), ct.(*rlwe.Ciphertext))
				}
				evt.Rescale(ct.(*rlwe.Ciphertext), ct.(*rlwe.Ciphertext))
				if finalRound && key == "" {
					//evt.Rescale(ct.(*rlwe.Ciphertext), ct.(*rlwe.Ciphertext))
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
func SpawnMultiplier(evt bfv.Evaluator, taskCh chan MultiplierTask) {
	for {
		task, ok := <-taskCh
		if !ok {
			//closed
			return
		}
		intermediateResult := make([]*rlwe.Ciphertext, 0)
		for _, op := range task.Values {
			intermediateResult = append(intermediateResult, evt.MulNew(task.Query, op))
		}
		//compress (accumulate result with lazy modswitch and relin) atomically
		task.ResultMap.Mux.Lock()

		if _, ok := task.ResultMap.Map[task.ResultKey]; !ok {
			task.ResultMap.Map[task.ResultKey] = make([]rlwe.Operand, 0)
		}
		result, _ := task.ResultMap.Map[task.ResultKey]
		for i := 0; i < utils.Min(len(intermediateResult), len(result)); i++ {
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
