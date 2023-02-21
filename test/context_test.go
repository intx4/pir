package test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"pir/settings"
	"strconv"
	"testing"
)

func TestContextGen(t *testing.T) {
	HC := make(map[string]settings.PirContext)
	for _, items := range []int{1 << 14, 1 << 16, 1 << 18, 1 << 20, 1 << 21, 1 << 22, 1 << 23, 1 << 24, 1 << 25, 1 << 26, 1 << 27, 1 << 28, 1 << 29} {
		for _, size := range []int{30 * 8, 150 * 8, 288 * 8, 1000 * 8} {
			fmt.Printf("DB SIZE = %f\n\n\n", float64(float64(items*size)/1e9))
			for _, logN := range []int{12, 13, 14} {
				for _, d := range []int{2, 3, 4, 5} {
					ctx, err := settings.NewPirContext(items, size, 1<<logN, d)
					if err != nil {
						t.Logf("LogN: %d, Dim: %d, Items: %d, size: %d, err: %s", logN, d, items, size/8, err.Error())
						continue
					}
					fmt.Printf("LogN: %d, K: %d, Kd : %d, Items per bin: %d, Dim: %d, Tot db size : %f\n\n", logN, ctx.K, ctx.Kd, ctx.MaxBinSize, d, float64(float64(ctx.K*ctx.MaxBinSize*size)/1e9))
					HC[strconv.FormatInt(int64(items), 10)+"|"+strconv.FormatInt(int64(size), 10)+"|"+strconv.FormatInt(int64(logN), 10)+"|"+strconv.FormatInt(int64(d), 10)] = *ctx
				}
			}
		}
	}
	j, _ := json.MarshalIndent(&settings.PirContexts{M: HC}, "", " ")
	_ = ioutil.WriteFile(DIR+"hypercube.json", j, 0666)
}
