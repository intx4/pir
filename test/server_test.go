package test

import (
	"pir"
	"pir/settings"
	"pir/utils"
	"testing"
)

// This test takes time
func TestServerEncode(t *testing.T) {
	items := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16}
	sizes := []int{150 * 8, 250 * 8}
	for _, item := range items {
		for _, size := range sizes {
			for _, dimentions := range []int{2, 3} {
				context, err := settings.NewPirContext(item, size, dimentions, 14, 65537, 16)
				if err != nil {
					t.Fatalf(err.Error())
				}
				box, err := settings.NewHeBox(context)
				if err != nil {
					t.Fatalf(err.Error())
				}
				keys := make([][]byte, item)
				values := make([][]byte, item)
				for i := range keys {
					keys[i] = RandByteString(100)
					values[i] = RandByteString(size)
				}
				server, err := pir.NewPirServer(context, box, keys, values)
				if err != nil {
					t.Fatalf(err.Error())
				}
				if ecdStore, err := server.Encode(); err != nil {
					t.Fatalf(err.Error())
				} else {
					for k, v := range ecdStore {
						expected := server.Store[k].Value
						actual := box.Ecd.DecodeUintNew(v[0])
						for i := 1; i < len(v); i++ {
							actual = append(actual, box.Ecd.DecodeUintNew(v[i])...)
						}
						actualBytes, err := utils.Unchunkify(actual, context.TUsable)
						if err != nil {
							t.Fatalf(err.Error())
							//chunks, _ := utils.Chunkify(server.Store[k].Value, context.TUsable)
							//_, err := utils.Unchunkify(chunks, context.TUsable)
							//fmt.Println(err.Error())
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
