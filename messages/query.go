package messages // Represents a compressed ct in a PIR query
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

// //Base element representing a query vector : uses a compression trick when ct is encrypted using sk rather than pk to reduce the size by 2
type PIRQueryItem struct {
	C0   *ring.Poly    `json:"c_0,omitempty"`
	Meta rlwe.MetaData `json:"meta"`
	Lvl  int           `json:"lvl,omitempty"`
	Deg  int           `json:"deg,omitempty"`
}

// Wrapper for both types of queries (with or without oblivious expansion)
type PIRQueryItemContainer struct {
	Compressed []*PIRQueryItem   `json:"compressed,omitempty"`
	Expanded   [][]*PIRQueryItem `json:"expanded,omitempty"`
}

// Represents a query from client
type PIRQuery struct {
	Q            *PIRQueryItemContainer `json:"q,omitempty"`
	Leakage      int                    `json:"leakage"`                 //0 (none) to 2 (max)
	Prefix       string                 `json:"prefix"`                  //hint for WPIR
	Seed         int64                  `json:"seed,omitempty"`          //seed for expansion
	ClientId     string                 `json:"id,omitempty"`            //unique id for storing crypto material (e.g evt keys)
	Profile      *settings.PIRProfile   `json:"profile, omitempty"`      //profile generated by client with crypto material
	FetchContext bool                   `json:"fetchContext, omitempty"` //true if client is just asking for the context for syncing
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
		C0:   ct.Value[0],
		Meta: ct.MetaData,
		Lvl:  ct.Level(),
		Deg:  ct.Degree(),
	}
}

// Decompress CT by sampling the random polynomial from seed. compressedCts can be a single PIRQueryItem, an array or list of arrays
// Returns an array of interfaces, where each entry can respectivelly be_
// - a ciphertext
// - an array of ciphertexts
func DecompressCT(compressedCTs interface{}, sampler ringqp.UniformSampler, params bfv.Parameters) ([]interface{}, error) {
	switch compressedCTs.(type) {
	case []*PIRQueryItem:
		decompressed := make([]interface{}, len(compressedCTs.([]*PIRQueryItem)))
		for i, compressed := range compressedCTs.([]*PIRQueryItem) {
			ct := bfv.NewCiphertext(params, compressed.Deg, compressed.Lvl)
			sampler.ReadLvl(compressed.Lvl, -1, ringqp.Poly{Q: ct.Value[1]})
			//skip InvNTT as NTT it's needed for Expand
			//params.RingQ().InvNTTLvl(compressed.Lvl, ct.Value[1], ct.Value[1])
			ct.MetaData = compressed.Meta
			ct.Value[0] = compressed.C0
			decompressed[i] = ct
		}
		return decompressed, nil
	case [][]*PIRQueryItem:
		decompressed := make([]interface{}, len(compressedCTs.([][]*PIRQueryItem)))
		for i := range decompressed {
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
		return decompressed, nil
	case *PIRQueryItem:
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
