package pir

import (
	"errors"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"pir/settings"
	"pir/utils"
	"strconv"
)

/*
Record of the PIR Database in bytes. It contains a value (that is a sequence of bytes, representing 1 or more data items)
*/
type PIREntry struct {
	Items int
	Value []byte
	L     int
}

func NewPirEntry(value []byte) *PIREntry {
	return &PIREntry{Items: 1, Value: value, L: len(value)}
}

func (PE *PIREntry) Update(newValue []byte, maxBinSize int) (int, error) {
	if len(newValue) != PE.L {
		return -1, errors.New(fmt.Sprintf("Byte length of data stored in this entry is not uniform. Old %d, new %d", PE.L, len(newValue)))
	}
	if PE.Items+1 > maxBinSize {
		return -1, errors.New(fmt.Sprintf("Entry size exceeded maximum bin size: %d > %d", PE.Items+1, maxBinSize))
	}
	PE.Value = append(PE.Value, newValue...)
	PE.Items++
	return PE.Items - 1, nil
}

func (PE *PIREntry) Modify(newValue []byte, pos int) error {
	if len(newValue) != PE.L {
		return errors.New(fmt.Sprintf("Byte length of data stored in this entry is not uniform. Old %d, new %d", PE.L, len(newValue)))
	}
	if pos > PE.Items || pos < 0 {
		return errors.New(fmt.Sprintf("Invalid position for update: %d/%d", pos, PE.Items))
	}
	for i := pos; i < pos+PE.L; i++ {
		PE.Value[i] = newValue[i-pos]
	}
	return nil
}

func (PE *PIREntry) Delete(pos int) error {
	if pos > PE.Items || pos < 0 {
		return errors.New(fmt.Sprintf("Invalid position for update: %d/%d", pos, PE.Items))
	}
	for i := pos; i < pos+PE.L; i++ {
		PE.Value[i] = PE.Value[i+PE.L]
	}
	PE.Value = PE.Value[:len(PE.Value)-PE.L]
	PE.Items--
	return nil
}

func (PE *PIREntry) Encode(t int, n int, box *settings.HeBox) ([]*bfv.PlaintextMul, error) {
	chunks, err := utils.Chunkify(PE.Value, t)
	if err != nil {
		return nil, err
	}
	return utils.EncodeChunks(chunks, box), nil
}

type PIRServer struct {
	Context *settings.PirContext
	Box     *settings.HeBox
	Store   map[string]*PIREntry
}

func NewPirServer(c *settings.PirContext, b *settings.HeBox, keys [][]byte, values [][]byte) (*PIRServer, error) {
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
				return nil, err
			}
			if collisions+1 > maxCollisions {
				maxCollisions = collisions + 1
			}
		} else {
			//store new
			PS.Store[k] = NewPirEntry(values[i])
		}
	}
	fmt.Printf("	Storage encoded in chunks : Max size of bucket = %d\n", maxCollisions)
	return PS, nil
}

func (PS *PIRServer) Encode() error {
	ecdStore := make(map[string][]*bfv.PlaintextMul)
	for k, e := range PS.Store {
		v, err := e.Encode(PS.Context.T, PS.Context.N, PS.Box)
		if err != nil {
			return err
		}
		ecdStore[k] = v
	}
	return nil
}

// Recursive function to generate keys at depth nextdepth = currdepth+1 (depth is a dimention)
func (PS *PIRServer) genKeysAtDepth(di string, nextDepth int, keys []string) {
	if nextDepth == PS.Context.Dimentions-1 {
		for dj := 0; dj < PS.Context.Kd; dj++ {
			keys = append(keys, di+"|"+strconv.FormatInt(int64(dj), 10))
		}
	} else if nextDepth > PS.Context.Dimentions {
		return
	} else {
		for dj := 0; dj < PS.Context.Kd; dj++ {
			PS.genKeysAtDepth(di+"|"+strconv.FormatInt(int64(dj), 10), nextDepth+1, keys)
		}
	}
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
func (PS *PIRServer) AnswerGen(ecdStore map[string][]rlwe.Operand, query [][]*rlwe.Ciphertext, rlk *rlwe.RelinearizationKey) ([]*rlwe.Ciphertext, error) {
	evt := PS.Box.Evt.WithKey(rlwe.EvaluationKey{Rlk: rlk})
	if PS.Context.Kd != len(query[0]) {
		return nil, errors.New(fmt.Sprintf("Query vector has not the right size. Expected %d got %d", PS.Context.Kd, len(query[0])))
	}
	if PS.Context.Dimentions != len(query) {
		return nil, errors.New(fmt.Sprintf("Dimentionality mismatch. Expected %d got %d", PS.Context.Dimentions, len(query)))
	}
	finalAnswer := make([]*rlwe.Ciphertext, 0)
	for d := 0; d < PS.Context.Dimentions; d++ {
		//loop over all dimentions of the hypercube
		q := query[d]
		newStore := make(map[string][]rlwe.Operand)
		keys := make([]string, 0)
		PS.genKeysAtDepth("", d+1, keys)
		for di := 0; di < PS.Context.Kd; di++ {
			//scan this dimention
			result := make([]*rlwe.Ciphertext, 0)
			if len(keys) > 0 {
				//recurring, update storage
				for _, k := range keys {
					nextK := k
					k = strconv.FormatInt(int64(di), 10) + k
					if e, ok := ecdStore[k]; ok {
						for _, op := range e {
							result = append(result, evt.MulNew(q[di], op))
						}
					}
					if e, ok := newStore[k]; ok {
						//compress (accumulate result with lazy modswitch and relin)
						if len(result) > 0 {
							for i := 0; i < len(e); i++ {
								e[i] = evt.AddNew(result[i], e[i])
							}
							if len(result) > len(e) {
								//this result is longer then the one we had, add the additional ciphertexts
								newItemsIdx := len(e)
								for len(e) < len(result) {
									e = append(e, result[newItemsIdx])
									newItemsIdx++
								}
							}
						}
					} else {
						//store new intermediate result
						if len(result) > 0 {
							newStore[nextK] = make([]rlwe.Operand, len(result))
							for i, ct := range result {
								newStore[nextK][i] = ct
							}
						}
					}
				}
			} else {
				//final dimention
				if e, ok := ecdStore[strconv.FormatInt(int64(di), 10)]; ok {
					for _, op := range e {
						result = append(result, evt.MulNew(q[di], op))
					}
				}
				if len(finalAnswer) == 0 {
					finalAnswer = result
				} else if len(result) > 0 {
					for i := 0; i < len(finalAnswer); i++ {
						evt.Add(result[i], finalAnswer[i], finalAnswer[i])
					}
					if len(result) > len(finalAnswer) {
						//this result is longer then the one we had, add the additional ciphertexts
						newItemsIdx := len(finalAnswer)
						for len(finalAnswer) < len(result) {
							finalAnswer = append(finalAnswer, result[newItemsIdx])
							newItemsIdx++
						}
					}
				}
			}
		}
		//relin and modswitch
		if d != PS.Context.Dimentions-1 {
			for _, e := range newStore {
				for _, ct := range e {
					evt.Relinearize(ct.(*rlwe.Ciphertext), ct.(*rlwe.Ciphertext))
					evt.Reduce(ct.(*rlwe.Ciphertext), ct.(*rlwe.Ciphertext))
				}
			}
			//update storage recursively
			ecdStore = newStore
		} else {
			for _, ct := range finalAnswer {
				evt.Relinearize(ct, ct)
			}
		}
	}
	return finalAnswer, nil
}
