package test

import (
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"pir/messages"
	Server "pir/server"
	"pir/settings"
	"pir/utils"
	"testing"
)

// Takes Time
func TestServerEncode(t *testing.T) {
	var items = []int{1 << 10, 1 << 12}
	var sizes = []int{150 * 8, 250 * 8, 1000 * 8}

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
					_, params := settings.GetsParamForPIR(logN, dimentions, true, false, messages.NONELEAKAGE)
					ctx, err := settings.NewPirContext(item, size, 1<<params.LogN(), dimentions)
					server, _ := Server.NewPirServer(ctx, db)
					//let's verify that values are encoded as expected

					if err != nil {
						t.Fatalf(err.Error())
					}
					box, _ := settings.NewHeBox(params)
					ecdStore := server.Store
					ecdStorageAsMap := make(map[string][]rlwe.Operand)
					ecdStore.Range(func(key, value any) bool {
						ecdStorageAsMap[key.(string)], _ = value.(*Server.PIRDBEntry).EncodeRLWE(settings.TUsableBits, box.Ecd.ShallowCopy(), params)
						return true
					})
					for k, v := range ecdStorageAsMap {
						entryFromDb, _ := ecdStore.Load(k)
						expected := entryFromDb.(*Server.PIRDBEntry).Coalesce()
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
