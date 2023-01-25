package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"google.golang.org/grpc"
	"log"
	"math"
	"math/rand"
	"pir"
	pb "pir/client/pb"
	"pir/settings"
	"pir/utils"
)

type PIRClient struct {
	context *settings.PirContext
	B       map[string]*settings.HeBox
	Pp      map[string]*settings.PIRProfile
	Id      string
}

func NewPirClient(id string) *PIRClient {
	client := new(PIRClient)
	client.Id = id
	client.Pp = map[string]*settings.PIRProfile{}
	client.B = map[string]*settings.HeBox{}
	return client
}

func (PC *PIRClient) AddContext(context *settings.PirContext) {
	PC.context = context
}

func (PC *PIRClient) GenProfile(expansion bool, weaklyPrivate bool, leakage int) (*settings.PIRProfile, error) {
	if PC.context == nil {
		return nil, errors.New("Need to initialize context")
	}
	var err error
	paramsID, params := settings.GetsParamForPIR(int(math.Log2(float64(PC.context.N))), PC.context.Dim, expansion, weaklyPrivate, leakage)
	if _, ok := PC.B[paramsID]; ok {
		return PC.Pp[paramsID], nil
	} else {
		PC.B[paramsID], err = settings.NewHeBox(params)
		if err != nil {
			return nil, err
		}
		PC.B[paramsID].GenSk()
		PC.Pp[paramsID] = &settings.PIRProfile{
			Rlk:     PC.B[paramsID].GenRelinKey(),
			Rtks:    PC.B[paramsID].GenRtksKeys(),
			Context: *PC.context,
		}
		return PC.Pp[paramsID], nil
	}
}

/*
Given a key, generates a query as a list of list ciphertexts to retrieve the element associated to the key
It assumes that both the querier and the server agree on the same context (i.e crypto params for BFV and key space)
key: key of the element (e.g a subset of the data items, like some keywords)
Returns a list of list of Ciphertexts. Each list is needed to query one of the dimentions of the DB seen as an hypercube.
Inside on of the sublists, you have a list of ciphers when only one is enc(1) to select the index of this dimention, until the last dimention when a plaintext value will be selected
*/
func (PC *PIRClient) QueryGen(key []byte, leakage int, expansion bool, weaklyPrivate, compressed bool) (*pir.PIRQuery, float64, error) {
	//new seeded prng
	ctx := PC.context
	seed := rand.Int63n(1<<63 - 1)
	prng, err := pir.NewPRNG(seed)
	if err != nil {
		panic(err)
	}
	paramsID, params := settings.GetsParamForPIR(int(math.Log2(float64(PC.context.N))), PC.context.Dim, expansion, weaklyPrivate, leakage)
	box := PC.B[paramsID]
	box.WithEncryptor(bfv.NewPRNGEncryptor(params, box.Sk).WithPRNG(prng))
	q := new(pir.PIRQuery)
	q.ClientId = PC.Id
	q.Seed = seed
	if PC.Pp == nil {
		return nil, 0.0, errors.New("Need to generate profile before query")
	}
	q.Profile = PC.Pp[paramsID]
	leakedBits := 0.0
	if !weaklyPrivate {
		if compressed {
			q.Q, err = PC.compressedQueryGen(key, ctx.Kd, ctx.Dim, box)
		} else {
			q.Q, err = PC.queryGen(key, *ctx, box)
		}
	} else {
		if compressed == false {
			return nil, 0, errors.New("WPIR queries are not supported without compression")
		}
		if leakage == pir.NONELEAKAGE {
			return nil, 0, errors.New("NONE leakage is supported only if not weakly private query")
		}
		s := 1.0
		if leakage == pir.STANDARDLEAKAGE {
			s = math.Floor(float64(ctx.Dim) / 2)
		}
		if leakage == pir.HIGHLEAKAGE {
			s = float64(ctx.Dim - 1)
		}

		leakedBits = (s / float64(ctx.Dim)) * math.Log2(float64(ctx.K))
		q.Q, err = PC.wpQueryGen(key, ctx.Kd, ctx.Dim, int(s), box)
	}
	return q, leakedBits, err
}

/*
Given a key, generates a query as a list of list ciphertexts to retrieve the element associated to the key
It assumes that both the querier and the server agree on the same context (i.e crypto params for BFV and key space)
key: key of the element (e.g a subset of the data items, like some keywords)
Returns a list of list of Ciphertexts. Each list is needed to query one of the dimentions of the DB seen as an hypercube.
Inside on of the sublists, you have a list of ciphers when only one is enc(1) to select the index of this dimention, until the last dimention when a plaintext value will be selected
*/
func (PC *PIRClient) queryGen(key []byte, ctx settings.PirContext, box *settings.HeBox) ([][]*pir.PIRQueryItem, error) {
	Kd, dimentions := ctx.Kd, ctx.Dim
	if box.Ecd == nil || box.Enc == nil || box.Dec == nil {
		return nil, errors.New("Client is not initialiazed with Encoder or Encryptor or Decryptor")
	}
	_, keys := utils.MapKeyToDim(key, Kd, dimentions)
	query := make([][]*pir.PIRQueryItem, dimentions)
	for i, k := range keys {
		queryOfDim := make([]*pir.PIRQueryItem, Kd)
		for d := 0; d < Kd; d++ {
			c := &rlwe.Ciphertext{}
			if d == k {
				//enc 1
				q := make([]uint64, box.Params.N())
				for j := 0; j < len(q); j++ {
					q[j] = 1
				}
				c = box.Enc.EncryptNew(box.Ecd.EncodeNew(q, box.Params.MaxLevel()))
			} else {
				//enc 0
				c = box.Enc.EncryptZeroNew(box.Params.MaxLevel())
			}
			queryOfDim[d] = pir.CompressCT(c)
		}
		query[i] = queryOfDim
	}
	return query, nil
}

func (PC *PIRClient) compressedQueryGen(key []byte, Kd, dimentions int, box *settings.HeBox) ([]*pir.PIRQueryItem, error) {
	if box.Ecd == nil || box.Enc == nil {
		return nil, errors.New("Client is not initliazed with Encoder or Encryptor")
	}
	//l := int(math.Ceil(float64(PC.Context.K) / float64(box.Params.N())))
	_, keys := utils.MapKeyToDim(key, Kd, dimentions)
	selectors := make([][]uint64, dimentions)

	//gen selection vectors
	for i, k := range keys {
		selectors[i] = make([]uint64, Kd)
		selectors[i][k] = 1
	}

	query := make([]*pir.PIRQueryItem, dimentions)
	enc := box.Enc
	ecd := box.Ecd

	for i := range query {
		ct := enc.EncryptNew(utils.EncodeCoeffs(ecd, box.Params, selectors[i]))
		query[i] = pir.CompressCT(ct)
	}
	return query, nil
}

func (PC *PIRClient) AnswerGet(paramsID string, answer []*rlwe.Ciphertext) ([]byte, error) {
	if box, ok := PC.B[paramsID]; !ok {
		return nil, errors.New("Params not found to decrypt answer")
	} else {
		res := make([]uint64, 0)
		for _, a := range answer {
			decrypted := box.Dec.DecryptNew(a)
			decoded := box.Ecd.DecodeUintNew(decrypted)
			res = append(res, decoded...)
		}
		value, err := utils.Unchunkify(res, settings.TUsableBits)
		if err != nil {
			return nil, err
		}
		return value, nil
	}
}

// |
// | W PIR
// v

func (PC *PIRClient) wpQueryGen(key []byte, Kd, dimentions, dimToSkip int, box *settings.HeBox) ([]*pir.PIRQueryItem, error) {
	if box.Ecd == nil || box.Enc == nil {
		return nil, errors.New("Client is not initliazed with Encoder or Encryptor")
	}
	//l := int(math.Ceil(float64(PC.Context.K) / float64(box.Params.N())))
	_, keys := utils.MapKeyToDim(key, Kd, dimentions)
	selectors := make([][]uint64, dimentions-dimToSkip)

	//gen selection vectors
	for i, k := range keys[dimToSkip:] {
		selectors[i] = make([]uint64, Kd)
		selectors[i][k] = 1
	}

	query := make([]*pir.PIRQueryItem, dimentions)
	enc := box.Enc
	ecd := box.Ecd

	for i := range query {
		if i < dimToSkip {
			query[i] = &pir.PIRQueryItem{IsPlain: true, Idx: keys[i]}
		} else {
			ct := enc.EncryptNew(utils.EncodeCoeffs(ecd, box.Params, selectors[i-dimToSkip]))
			query[i] = pir.CompressCT(ct)
		}
	}
	return query, nil
}

// Sends query to ICF via gRPC service in Python. Address is of form "ip:port"
func (PC *PIRClient) SendQuery(query *pir.PIRQuery, address string) ([]*rlwe.Ciphertext, error) {
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer conn.Close()

	client := pb.NewInternalClientClient(conn)
	data, err := json.Marshal(query)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	req := pb.InternalRequest{
		Query: base64.StdEncoding.EncodeToString(data),
	}
	resp, err := client.Query(context.Background(), &req)
	answerDec, err := base64.StdEncoding.DecodeString(resp.Answer)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	pirAnswer := &pir.PIRAnswer{}
	err = json.Unmarshal(answerDec, pirAnswer)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return pirAnswer.Answer, err
}
