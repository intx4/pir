package test

import (
	"bytes"
	"pir"
	"pir/settings"
	"pir/utils"
	"testing"
)

// This test takes time
func TestServerEncode(t *testing.T) {
	//various settings for the db size
	items := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16}
	sizes := []int{150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			for _, dimentions := range []int{2, 3} {
				//we first create a context for the protocol, including info about the db size
				//the dimentions we need to represent the db by (e.g 2 for matrix representation)
				//the parameters of the BFV scheme (N,T and usable bits of T)
				context, err := settings.NewPirContext(item, size, dimentions, 14, 65537, 16)
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
				if err != nil {
					t.Fatalf(err.Error())
				}
				//let's verify that values are encoded as expected
				if ecdStore, err := server.Encode(); err != nil {
					t.Fatalf(err.Error())
				} else {
					for k, v := range ecdStore {
						expected := server.Store[k].Coalesce()
						actual := box.Ecd.DecodeUintNew(v[0])
						for i := 1; i < len(v); i++ {
							actual = append(actual, box.Ecd.DecodeUintNew(v[i])...)
						}
						actualBytes, err := utils.Unchunkify(actual, context.TUsable)
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
				context, err := settings.NewPirContext(item, size, dimentions, 14, 65537, 16)
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
				k, _ := utils.MapKeyToIdx(keys[0], context.Kd, context.Dimentions)
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
