package pir

import (
	"golang.org/x/exp/rand"
	"gonum.org/v1/gonum/stat/distuv"
	"math"
	"pir/utils"
	"runtime"
	"sync"
)

var DBSizeUpperBound = 1 << 20

// This module holds the logic for Differential Obliviousness
type DiffOblModule struct {
	DBSize      int
	Eps         float64
	Delta       float64
	N           int
	H           []int
	QueriesDone int
	source      rand.Source
}

func NewDOModule(DBsize int, eps, delta float64, n int) *DiffOblModule {
	return &DiffOblModule{
		DBSize:      DBsize,
		Eps:         eps,
		Delta:       delta,
		N:           n,
		QueriesDone: 0,
		H:           nil,
		source:      rand.NewSource(rand.Uint64()),
	}
}

// Algo 6 from https://eprint.iacr.org/2020/1596.pdf
func (DO *DiffOblModule) GenDPHistogram() {
	DBsize := DO.DBSize
	n := DO.N
	eps := DO.Eps
	delta := DO.Delta
	f := float64(2*n) / eps //sensitivity
	L := distuv.Laplace{
		Mu:    0,
		Scale: f,
		Src:   DO.source,
	}
	B := utils.Min(float64(DBsize), math.Abs(L.Quantile(delta/2))) //clipping
	h := make([]int, DBsize)
	var wg sync.WaitGroup
	pool := make(chan struct{}, runtime.NumCPU())
	for i := 0; i < runtime.NumCPU(); i++ {
		pool <- struct{}{}
	}
	for i := range h {
		<-pool
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := L.Rand()
			u = utils.Max(0, B+utils.Min(B, u))
			h[i] = int(u)
			pool <- struct{}{}
		}(i)
	}
	wg.Wait()
	DO.H = h
}

func (DO *DiffOblModule) UpdateQueryCount() {
	DO.QueriesDone++
	if DO.QueriesDone > DO.N {
		panic("STATISTICAL PRIVACY CAN NO LONGER BE GUARANTEED!")
	}
}
