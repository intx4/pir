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
	"pir/settings"
)

const (
	NONELEAKAGE int = iota
	STANDARDLEAKAGE
	HIGHLEAKAGE
)

func NewPRNG(seed int64) (*utils2.KeyedPRNG, error) {
	rand.Seed(seed)
	keyPRNG := make([]byte, 64)
	rand.Read(keyPRNG)
	prng, err := utils2.NewKeyedPRNG(keyPRNG)
	if err != nil {
		return nil, err
	}
	return prng, nil
}
func NewSampler(seed int64, params bfv.Parameters) (*ringqp.UniformSampler, error) {
	prng, err := NewPRNG(seed)
	if err != nil {
		return nil, err
	}
	sampler := ringqp.NewUniformSampler(prng, *params.RingQP())
	return &sampler, nil
}

// Uses a compression trick when ct is encrypted using sk rather than pk to reduce the size by 2
type PIRQueryItem struct {
	IsPlain bool          `json:"IsPlain"`
	Idx     int           `json:"idx"`
	C0      *ring.Poly    `json:"c_0,omitempty"`
	Meta    rlwe.MetaData `json:"meta"`
	Lvl     int           `json:"lvl,omitempty"`
	Deg     int           `json:"deg,omitempty"`
}

type PIRQuery struct {
	Q            interface{}          `json:"q,omitempty"`
	Seed         int64                `json:"seed,omitempty"`
	ClientId     string               `json:"id,omitempty"`
	Profile      *settings.PIRProfile `json:"profile, omitempty"`
	ByGUTI       bool                 `json:"byGUTI, omitempty"`
	FetchContext bool                 `json:"fetchContext, omitempty"`
}

func (PQ *PIRQueryItem) MarshalBinary() ([]byte, error) {
	b, err := json.Marshal(PQ)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (PQ *PIRQueryItem) UnMarshalBinary(b []byte) error {
	return json.Unmarshal(b, PQ)
}

func CompressCT(ct *rlwe.Ciphertext) *PIRQueryItem {
	return &PIRQueryItem{
		IsPlain: false,
		C0:      ct.Value[0],
		Meta:    ct.MetaData,
		Lvl:     ct.Level(),
		Deg:     ct.Degree(),
	}
}

// Decompress CT by sampling the random polynomial from seed. compressedCts can be a single PIRQueryItem, an array or list of arrays
// Returns an array of interfaces, where each entry can respectivelly be_
// - a ciphertext or integer
// - an array of ciphertexts or integers
func DecompressCT(compressedCTs interface{}, sampler ringqp.UniformSampler, params bfv.Parameters) ([]interface{}, error) {
	switch compressedCTs.(type) {
	case []*PIRQueryItem:
		decompressed := make([]interface{}, len(compressedCTs.([]*PIRQueryItem)))
		for i, compressed := range compressedCTs.([]*PIRQueryItem) {
			if compressed.IsPlain {
				decompressed[i] = compressed.Idx
			} else {
				ct := bfv.NewCiphertext(params, compressed.Deg, compressed.Lvl)
				sampler.ReadLvl(compressed.Lvl, -1, ringqp.Poly{Q: ct.Value[1]})
				//skip InvNTT as NTT it's needed for Expand
				//params.RingQ().InvNTTLvl(compressed.Lvl, ct.Value[1], ct.Value[1])
				ct.MetaData = compressed.Meta
				ct.Value[0] = compressed.C0
				decompressed[i] = ct
			}
		}
		return decompressed, nil
	case [][]*PIRQueryItem:
		decompressed := make([]interface{}, len(compressedCTs.([][]*PIRQueryItem)))
		for i := range decompressed {
			if compressedCTs.([][]*PIRQueryItem)[i][0].IsPlain {
				decompressed[i] = compressedCTs.([][]*PIRQueryItem)[i][0].Idx
			} else {
				decompressed[i] = make([]*rlwe.Ciphertext, len(compressedCTs.([][]*PIRQueryItem)[i]))
				for j, compressed := range compressedCTs.([][]*PIRQueryItem)[i] {
					ct := bfv.NewCiphertext(params, compressed.Deg, compressed.Lvl)
					sampler.ReadLvl(compressed.Lvl, -1, ringqp.Poly{Q: ct.Value[1]})
					params.RingQ().InvNTTLvl(compressed.Lvl, ct.Value[1], ct.Value[1])
					ct.MetaData = compressed.Meta
					ct.Value[0] = compressed.C0
					decompressed[i].([]*rlwe.Ciphertext)[j] = ct
				}
			}
		}
		return decompressed, nil
	case *PIRQueryItem:
		if compressedCTs.(*PIRQueryItem).IsPlain {
			return []interface{}{compressedCTs.(*PIRQueryItem).Idx}, nil
		}
		ct := bfv.NewCiphertext(params, compressedCTs.(*PIRQueryItem).Deg, params.MaxLevel())
		sampler.ReadLvl(compressedCTs.(*PIRQueryItem).Lvl, -1, ringqp.Poly{Q: ct.Value[1]})
		params.RingQ().InvNTTLvl(compressedCTs.(*PIRQueryItem).Lvl, ct.Value[1], ct.Value[1])
		ct.MetaData = compressedCTs.(*PIRQueryItem).Meta
		ct.Value[0] = compressedCTs.(*PIRQueryItem).C0
		return []interface{}{ct}, nil
	default:
		break
	}
	return nil, errors.New(fmt.Sprintf("Unknown tipe %T", compressedCTs))
}
