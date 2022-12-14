package pir // Represents a compressed ct in a PIR query
import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
	utils2 "github.com/tuneinsight/lattigo/v4/utils"
	"math/rand"
)

func NewSampler(seed int64, params bfv.Parameters) (*ringqp.UniformSampler, error) {
	rand.Seed(seed)
	keyPRNG := make([]byte, 64)
	rand.Read(keyPRNG)
	prng, err := utils2.NewKeyedPRNG(keyPRNG)
	if err != nil {
		return nil, err
	}
	sampler := ringqp.NewUniformSampler(prng, *params.RingQP())
	return &sampler, nil
}

// Uses a compression trick when ct is encrypted using sk rather than pk to reduce the size by 2
type PIRQueryCt struct {
	C0   *ring.Poly    `json:"c_0,omitempty"`
	Meta rlwe.MetaData `json:"meta"`
	Lvl  int           `json:"lvl,omitempty"`
	Deg  int           `json:"deg,omitempty"`
}

func (PQ *PIRQueryCt) MarshalBinary() ([]byte, error) {
	b, err := json.Marshal(PQ)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (PQ *PIRQueryCt) UnMarshalBinary(b []byte) error {
	return json.Unmarshal(b, PQ)
}

func CompressCT(ct *rlwe.Ciphertext) *PIRQueryCt {
	return &PIRQueryCt{
		C0:   ct.Value[0],
		Meta: ct.MetaData,
		Lvl:  ct.Level(),
		Deg:  ct.Degree(),
	}
}

// Decompress CT by sampling the random polynomial from seed
func DecompressCT(compressedCTs interface{}, sampler ringqp.UniformSampler, params bfv.Parameters) (interface{}, error) {
	switch compressedCTs.(type) {
	case []*PIRQueryCt:
		decompressed := make([]*rlwe.Ciphertext, len(compressedCTs.([]*PIRQueryCt)))
		for i, compressed := range compressedCTs.([]*PIRQueryCt) {
			ct := bfv.NewCiphertext(params, compressed.Deg, compressed.Lvl)
			sampler.ReadLvl(compressed.Lvl, -1, ringqp.Poly{Q: ct.Value[1]})
			params.RingQ().InvNTTLvl(compressed.Lvl, ct.Value[1], ct.Value[1])
			ct.MetaData = compressed.Meta
			ct.Value[0] = compressed.C0
			decompressed[i] = ct
		}
		return decompressed, nil
	case [][]*PIRQueryCt:
		decompressed := make([][]*rlwe.Ciphertext, len(compressedCTs.([][]*PIRQueryCt)))
		for i := range decompressed {
			decompressed[i] = make([]*rlwe.Ciphertext, len(compressedCTs.([][]*PIRQueryCt)[i]))
			for j, compressed := range compressedCTs.([][]*PIRQueryCt)[i] {
				ct := bfv.NewCiphertext(params, compressed.Deg, compressed.Lvl)
				sampler.ReadLvl(compressed.Lvl, -1, ringqp.Poly{Q: ct.Value[1]})
				params.RingQ().InvNTTLvl(compressed.Lvl, ct.Value[1], ct.Value[1])
				ct.MetaData = compressed.Meta
				ct.Value[0] = compressed.C0
				decompressed[i][j] = ct
			}
		}
		return decompressed, nil
	case *PIRQueryCt:
		ct := bfv.NewCiphertext(params, compressedCTs.(*PIRQueryCt).Deg, compressedCTs.(*PIRQueryCt).Lvl)
		sampler.ReadLvl(compressedCTs.(*PIRQueryCt).Lvl, -1, ringqp.Poly{Q: ct.Value[1]})
		params.RingQ().InvNTTLvl(compressedCTs.(*PIRQueryCt).Lvl, ct.Value[1], ct.Value[1])
		ct.MetaData = compressedCTs.(*PIRQueryCt).Meta
		ct.Value[0] = compressedCTs.(*PIRQueryCt).C0
		return ct, nil
	default:
		break
	}
	return nil, errors.New(fmt.Sprintf("Unknown tipe %T", compressedCTs))
}
