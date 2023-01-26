package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/sirupsen/logrus"
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

type PIRRequest struct {
	Key           []byte
	Expansion     bool
	WeaklyPrivate bool
	Leakage       int
}

type PIRClient struct {
	Context      *settings.PirContext
	B            map[string]*settings.HeBox
	Pp           map[string]*settings.PIRProfile
	Id           string
	RequestChan  chan *PIRRequest
	ResponseChan chan []byte
	IqfAddr      string
}

func NewPirClient(id string, iqfAddr string, requestChan chan *PIRRequest, responseChan chan []byte) *PIRClient {
	client := new(PIRClient)
	client.Id = id
	client.Pp = map[string]*settings.PIRProfile{}
	client.B = map[string]*settings.HeBox{}
	client.RequestChan = requestChan
	client.ResponseChan = responseChan
	client.IqfAddr = iqfAddr
	return client
}

// Starts client: first it fetches the context
func (PC *PIRClient) Start() {
	request := PC.ContextReqGen()
	leakedBits := 0.0
	for true {
		answer, err := PC.SendQuery(request, PC.IqfAddr)
		if err != nil {
			if PC.Context == nil {
				utils.Logger.WithFields(logrus.Fields{"service": "client", "error": err.Error()}).Error("Could not fetch context")
				panic("Could not fetch context")
			}
			utils.Logger.WithFields(logrus.Fields{"service": "client", "error": err.Error()}).Error("Error")
			go func(err error) { PC.ResponseChan <- []byte(err.Error()) }(err)
			continue
		}
		payload, prof, err := PC.ParseAnswer(answer)
		if err != nil {
			if PC.Context == nil {
				utils.Logger.WithFields(logrus.Fields{"service": "client", "error": err.Error()}).Error("Could not fetch context")
				panic("Could not fetch context")
			} else {
				utils.Logger.WithFields(logrus.Fields{"service": "client", "error": err.Error()}).Error("Error")
				go func(err error) { PC.ResponseChan <- []byte(err.Error()) }(err)
				continue
			}
		} else {
			if prof != nil {
				utils.Logger.WithFields(logrus.Fields{"service": "client", "profile": prof, "context": PC.Context}).Info("Fetched context and set profile")
			}
			if payload != "" {
				utils.Logger.WithFields(logrus.Fields{"service": "client", "payload": payload, "leak": leakedBits}).Info("Answer")
			}
			//wait for requests from frontend
			err = errors.New("Invalid request")
			for err != nil {
				command := <-PC.RequestChan
				request, leakedBits, err = PC.QueryGen(command.Key, PC.B[settings.ParamsToString(answer.Params)].Params.ParametersLiteral(), command.Leakage, command.Expansion, command.WeaklyPrivate, true)
				if err != nil {
					utils.Logger.WithFields(logrus.Fields{"service": "client", "error": err.Error()}).Error("Error generating query")
					go func(err error) { PC.ResponseChan <- []byte(err.Error()) }(err)
				}
			}
		}
	}
}

func (PC *PIRClient) AddContext(context *settings.PirContext) {
	PC.Context = context
}

// Generate profile given a set of parameters and stores it, if not already present. Context must be previously set
func (PC *PIRClient) GenProfile(literal bfv.ParametersLiteral) (*settings.PIRProfile, error) {
	if PC.Context == nil {
		return nil, errors.New("Need to initialize context")
	}
	var err error
	params, err := bfv.NewParametersFromLiteral(literal)
	if err != nil {
		return nil, err
	}
	if _, ok := PC.B[settings.ParamsToString(literal)]; ok {
		return PC.Pp[settings.ParamsToString(literal)], nil
	} else {
		PC.B[settings.ParamsToString(literal)], err = settings.NewHeBox(params)
		if err != nil {
			return nil, err
		}
		PC.B[settings.ParamsToString(literal)].GenSk()
		PC.Pp[settings.ParamsToString(literal)] = &settings.PIRProfile{
			Rlk:     PC.B[settings.ParamsToString(literal)].GenRelinKey(),
			Rtks:    PC.B[settings.ParamsToString(literal)].GenRtksKeys(),
			Context: *PC.Context,
		}
		return PC.Pp[settings.ParamsToString(literal)], nil
	}
}

// generates query to download context and params
func (PC *PIRClient) ContextReqGen() *pir.PIRQuery {
	return &pir.PIRQuery{
		Q:            nil,
		Seed:         0,
		ClientId:     PC.Id,
		Profile:      nil,
		ByGUTI:       false,
		FetchContext: true,
	}
}

/*
Given a key, generates a query as a list of list ciphertexts to retrieve the element associated to the key
It assumes that both the querier and the server agree on the same context (i.e crypto params for BFV and key space)
key: key of the element (e.g a subset of the data items, like some keywords)
Returns a list of list of Ciphertexts. Each list is needed to query one of the dimentions of the DB seen as an hypercube.
Inside on of the sublists, you have a list of ciphers when only one is enc(1) to select the index of this dimention, until the last dimention when a plaintext value will be selected
*/
func (PC *PIRClient) QueryGen(key []byte, params bfv.ParametersLiteral, leakage int, expansion bool, weaklyPrivate, compressed bool) (*pir.PIRQuery, float64, error) {
	//new seeded prng
	ctx := PC.Context
	seed := rand.Int63n(1<<63 - 1)
	prng, err := pir.NewPRNG(seed)
	if err != nil {
		panic(err)
	}
	box := PC.B[settings.ParamsToString(params)]
	box.WithEncryptor(bfv.NewPRNGEncryptor(box.Params, box.Sk).WithPRNG(prng))
	q := new(pir.PIRQuery)
	q.ClientId = PC.Id
	q.Seed = seed
	if PC.Pp == nil {
		return nil, 0.0, errors.New("Need to generate profile before query")
	}
	q.Profile = PC.Pp[settings.ParamsToString(params)]
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

// Returns string from DB if any, profile if generated after a fetch request, and error
// It also automatically updates context with the one sent by server and generates a new profile accordingly if needed
func (PC *PIRClient) ParseAnswer(answer *pir.PIRAnswer) (string, *settings.PIRProfile, error) {
	if answer.Ok {
		if answer.Answer == nil {
			PC.AddContext(answer.Context)
			prof, err := PC.GenProfile(answer.Params)
			if err != nil {
				return "", nil, err
			}
			return "", prof, nil
		} else {
			data, err := PC.AnswerGet(answer.Params, answer.Answer)
			if err != nil {
				return "", nil, err
			} else {
				return string(data), nil, nil
			}
		}
	} else {
		return "", nil, errors.New(answer.Error)
	}
}

func (PC *PIRClient) AnswerGet(params bfv.ParametersLiteral, answer []*rlwe.Ciphertext) ([]byte, error) {
	if box, ok := PC.B[settings.ParamsToString(params)]; !ok {
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

// GRPC
// |
// v

// Sends query to ICF via gRPC service in Python. Address is of form "ip:port"
func (PC *PIRClient) SendQuery(query *pir.PIRQuery, address string) (*pir.PIRAnswer, error) {
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
	return pirAnswer, err
}
