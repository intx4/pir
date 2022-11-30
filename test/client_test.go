package test

import (
	"math/rand"
	"pir"
	"pir/settings"
	"pir/utils"
	"testing"
)

func TestClientQueryGen(t *testing.T) {
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
				client := pir.NewPirClient(context, box)

				keys := make([][]byte, item)
				values := make([][]byte, item)
				for i := range keys {
					keys[i] = RandByteString(100)
					values[i] = RandByteString(size)
				}

				choice := len(keys)
				for choice > len(keys) || choice < 0 {
					choice = rand.Int()
				}
				_, choosenIdx := utils.MapKeyToIdx(keys[choice], context.Kd, context.Dimentions)
				query, err := client.QueryGen(keys[choice])
				if err != nil {
					t.Fatalf(err.Error())
				}
				for d, di := range choosenIdx {
					q := query[d]
					for i, ct := range q {
						pt := client.Box.Dec.DecryptNew(ct)
						v := client.Box.Ecd.DecodeUintNew(pt)
						if i == di {
							for _, n := range v {
								if n != uint64(1) {
									t.Fatalf("Expected 1 got %d at index %d", n, di)
								}
							}
						} else {
							for _, n := range v {
								if n != uint64(0) {
									t.Fatalf("Expected 0 got %d at index %d", n, di)
								}
							}
						}
					}
				}
			}
		}
	}
}
