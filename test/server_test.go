package test

import (
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"pir"
	Server "pir/server"
	"pir/settings"
	"pir/utils"
	"testing"
)

// Takes Time
func TestServerEncode(t *testing.T) {
	var items = []int{1 << 10, 1 << 12}
	var sizes = []int{150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			//fake db
			keys := make([]string, item)
			values := make([][]byte, item)
			db := make(map[string][]byte)
			for i := 0; i < len(keys); {
				keys[i] = string(RandByteString(100))
				values[i] = RandByteString(size / 8)
				if _, ok := db[keys[i]]; !ok {
					db[keys[i]] = values[i]
					i++
				}
			}
			for _, dimentions := range []int{2, 3} {
				for _, logN := range []int{13, 14} {
					params := settings.GetsParamForPIR(logN, dimentions, false, false, pir.NONELEAKAGE)
					server := Server.NewPirServer()
					//let's verify that values are encoded as expected
					ctx, err := settings.NewPirContext(item, size, 1<<params.LogN(), dimentions)
					if err != nil {
						t.Fatalf(err.Error())
					}
					box, _ := settings.NewHeBox(params)
					if ecdStore, err := server.Encode(ctx, []interface{}{}, db); err != nil {
						t.Fatalf(err.Error())
					} else {
						ecdStorageAsMap := make(map[string][]rlwe.Operand)
						ecdStore.Range(func(key, value any) bool {
							ecdStorageAsMap[key.(string)], _ = value.(*Server.PIREntry).Encode(settings.TUsableBits, box.Ecd.ShallowCopy(), params)
							return true
						})
						for k, v := range ecdStorageAsMap {
							entryFromDb, _ := server.Store.Load(k)
							expected := entryFromDb.(*Server.PIREntry).Coalesce()
							actual := box.Ecd.DecodeUintNew(v[0].(*bfv.PlaintextMul))
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
func TestServerEncodeWPIR(t *testing.T) {
	var items = []int{1 << 10, 1 << 12}
	var sizes = []int{150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			//fake db
			keys := make([]string, item)
			values := make([][]byte, item)
			db := make(map[string][]byte)
			for i := 0; i < len(keys); {
				keys[i] = string(RandByteString(100))
				values[i] = RandByteString(size / 8)
				if _, ok := db[keys[i]]; !ok {
					db[keys[i]] = values[i]
					i++
				}
			}
			for _, dimentions := range []int{2, 3} {
				for _, logN := range []int{13, 14} {
					params := settings.GetsParamForPIR(logN, dimentions, true, true, pir.HIGHLEAKAGE)
					server := Server.NewPirServer()
					//let's verify that values are encoded as expected
					ctx, err := settings.NewPirContext(item, size, 1<<params.LogN(), dimentions)
					if err != nil {
						t.Fatalf(err.Error())
					}
					box, _ := settings.NewHeBox(params)
					if ecdStore, err := server.Encode(ctx, []interface{}{1, 2}, db); err != nil {
						t.Fatalf(err.Error())
					} else {
						ecdStorageAsMap := make(map[string][]rlwe.Operand)
						ecdStore.Range(func(key, value any) bool {
							ecdStorageAsMap[key.(string)], _ = value.(*Server.PIREntry).Encode(settings.TUsableBits, box.Ecd, params)
							return true
						})
						for k, v := range ecdStorageAsMap {
							entryFromDb, _ := server.Store.Load(k)
							expected := entryFromDb.(*Server.PIREntry).Coalesce()
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
