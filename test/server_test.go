package test

import (
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"pir"
	"pir/settings"
	"pir/utils"
	"testing"
)

// This test takes time
func TestServerEncode(t *testing.T) {
	//various settings for the db size
	items := []int{1 << 10, 1 << 12}
	sizes := []int{150 * 8, 250 * 8}

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
					box, err := settings.NewHeBox(logN, dimentions, false)
					if err != nil {
						t.Fatalf(err.Error())
					}
					ctx, err := settings.NewPirContext(item, size, box.Params)
					if err != nil {
						t.Fatalf(err.Error())
					}
					server := pir.NewPirServer(db)
					if err != nil {
						t.Fatalf(err.Error())
					}
					//let's verify that values are encoded as expected
					server.AddProfile(&settings.PIRProfile{
						Rlk:  nil,
						Rtks: nil,
						LogN: logN,
						Q:    box.Params.Q(),
						P:    box.Params.P(),
						Id:   0,
					})
					K, Kd := settings.RoundUpToDim(float64(ctx.PackedSize), dimentions)
					mockQuery := &pir.PIRQuery{
						Q:          nil,
						Seed:       0,
						K:          K,
						Dimentions: dimentions,
						Kd:         Kd,
						Ks:         nil,
						Id:         0,
					}
					if ecdStore, box, err := server.Encode(ctx, mockQuery); err != nil {
						t.Fatalf(err.Error())
					} else {
						ecdStorageAsMap := make(map[string][]*bfv.PlaintextMul)
						ecdStore.Range(func(key, value any) bool {
							valueToStore := make([]*bfv.PlaintextMul, len(value.([]rlwe.Operand)))
							for i, v := range value.([]rlwe.Operand) {
								valueToStore[i] = v.(*bfv.PlaintextMul)
							}
							ecdStorageAsMap[key.(string)] = valueToStore
							return true
						})
						for k, v := range ecdStorageAsMap {
							expected := server.Store[k].Coalesce()
							actual := box.Ecd.DecodeUintNew(v[0])
							for i := 1; i < len(v); i++ {
								actual = append(actual, box.Ecd.DecodeUintNew(v[i])...)
							}
							actualBytes, err := utils.Unchunkify(actual, settings.TUsableBits)
							if err != nil {
								t.Fatalf(err.Error())
							}
							if len(actualBytes) != len(expected) {
								t.Fatalf("Len of decoded value is not same as original")
							}
							for i := range expected {
								if actualBytes[i] != expected[i] {
									t.Fatalf("Decoded value does not match original")
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
func TestServerEntryManipulation(t *testing.T) {
	//various settings for the db size
	items := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16}
	sizes := []int{150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			for _, dimentions := range []int{2, 3} {
				//we first create a context for the protocol, including info about the db size
				//the dimentions we need to represent the db by (e.g 2 for matrix representation)
				//the parameters of the BFV scheme (N,T and usable bits of T)
				context, err := settings.NewPirContext(item, size, dimentions, 14, 65537, 16, false)
				if err != nil {
					t.Fatalf(err.Error())
				}
				//we then create a HeBox with the context. This wraps all the tools needed for crypto stuff
				box, err := settings.NewHeBox(context)
				if err != nil {
					t.Fatalf(err.Error())
				}
				//let's generate some fake values
				keys := make([][]byte, item)
				values := make([][]byte, item)
				for i := range keys {
					keys[i] = RandByteString(100)
					values[i] = RandByteString(size)
				}
				server, err := pir.NewPirServer(*context, *box, keys, values)
				k, _ := utils.MapKeyToDim(keys[0], context.Kd, context.Dimentions)
				oldV := server.Store[k].Value
				if err != nil {
					t.Fatalf(err.Error())
				}
				pos1, err := server.Add(keys[0], values[0])
				if err != nil {
					t.Fatalf(err.Error())
				}
				pos2, err := server.Add(keys[0], values[1])
				if err != nil {
					t.Fatalf(err.Error())
				}
				err = server.Modify(keys[0], values[1], pos1)
				if err != nil {
					t.Fatalf(err.Error())
				}
				err = server.Modify(keys[0], values[2], pos2)
				if err != nil {
					t.Fatalf(err.Error())
				}
				err = server.Delete(keys[0], pos1)
				if err != nil {
					t.Fatalf(err.Error())
				}
				err = server.Delete(keys[0], pos2-1)
				for i := range oldV {
					if bytes.Compare(oldV[i], server.Store[k].Value[i]) != 0 {
						t.Fatalf("Comparison fail")
					}
				}
			}
		}
	}
}
*/
