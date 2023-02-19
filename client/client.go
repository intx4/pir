/*
Package implementing PIR client
*/
package client

import (
	"bytes"
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
	pb "pir/client/pb"
	"pir/messages"
	"pir/server"
	"pir/settings"
	"pir/utils"
	"strconv"
	"time"
)

type InternalRequest struct {
	// Sent from backend to pir logic
	Key           []byte
	Expansion     bool
	WeaklyPrivate bool
	Leakage       int
}

type InternalResponse struct {
	// From client to backend
	Payload []*server.ICFRecord `json:"payload,omitempty"`
	Leakage float64             `json:"leakage"`
	Latency float64             `json:"latency"`
	Error   error               `json:"error,omitempty"`
}
type RequestChannel chan *InternalRequest
type ResponseChannel chan *InternalResponse

type PIRClient struct {
	//Defines the client for the PIR protocol
	Context      *settings.PirContext
	Pp           map[string]*settings.PIRProfileSet
	Id           string
	RequestChan  RequestChannel
	ResponseChan ResponseChannel
	GrpcAddrPort string
}

// Returns a new PIR Client. Must provide unique id (used at server-side for storing crypto material),
// grpc address and port of the proxy to forward requests to IQF
// and channels for internal communication with backend
func NewPirClient(id string, grpcAddrPort string, requestChan RequestChannel, responseChan ResponseChannel) *PIRClient {
	client := new(PIRClient)
	client.Id = id
	client.Pp = make(map[string]*settings.PIRProfileSet)
	client.RequestChan = requestChan
	client.ResponseChan = responseChan
	client.GrpcAddrPort = grpcAddrPort
	return client
}

// Starts client: first it fetches the context, then listen for new queries (blocking)
func (PC *PIRClient) Start() {
	utils.Logger.WithFields(logrus.Fields{"service": "GRPC"}).Info("Fetching context")
	PC.RequireContext()
	utils.Logger.WithFields(logrus.Fields{"service": "GRPC"}).Info("Context fetched")
	PC.ListenForQueries()
}

// Listen for queries from backend
func (PC *PIRClient) ListenForQueries() {
	utils.Logger.WithFields(logrus.Fields{"service": "GRPC"}).Info("Listening for queries...")
	for true {
		command := <-PC.RequestChan
		if profile, ok := PC.Pp[PC.Context.Hash()].P[command.Leakage]; !ok {
			go func() {
				PC.ResponseChan <- &InternalResponse{Error: errors.New("Profile not found for leakage setting")}
			}()
			continue
		} else {
			start := time.Now()
			request, leakedBits, err := PC.QueryGen(command.Key, profile, command.Leakage, command.WeaklyPrivate, command.Expansion, true)
			if err != nil {
				utils.Logger.WithFields(logrus.Fields{"service": "client", "error": err.Error()}).Error("Error generating query")
				go func(err error) {
					PC.ResponseChan <- &InternalResponse{Error: err}
				}(err)
				continue
			}
			answer, err := PC.SendQuery(request, PC.GrpcAddrPort)
			if err != nil {
				utils.Logger.WithFields(logrus.Fields{"service": "client", "error": err.Error()}).Error("Error")
				go func(err error) {
					PC.ResponseChan <- &InternalResponse{Error: err}
				}(err)
				continue
			}
			payload, err := PC.ParseAnswer(answer, profile)
			if err != nil {
				utils.Logger.WithFields(logrus.Fields{"service": "client", "error": err.Error()}).Error("Error")
				go func(err error) {
					PC.ResponseChan <- &InternalResponse{Error: err}
				}(err)
				continue
			} else {
				if payload != nil {
					records, err := PC.decodeICFRecords(payload)
					if err != nil {
						utils.Logger.WithFields(logrus.Fields{"service": "client", "error": err.Error()}).Error("Error decoding ICF records")
						go func(err error) {
							PC.ResponseChan <- &InternalResponse{Error: err}
						}(err)
						continue
					} else {
						utils.Logger.WithFields(logrus.Fields{"service": "client", "payload": string(payload), "leak": leakedBits}).Info("Answer")
						end := time.Since(start).Seconds()
						go func(records []*server.ICFRecord, leakedBits float64, end float64) {
							PC.ResponseChan <- &InternalResponse{Payload: records, Leakage: leakedBits, Latency: end}
						}(records, leakedBits/float64(PC.Context.Items), end)
						continue
					}
				}
			}
		}
	}
}

// Sets new context
func (PC *PIRClient) AddContext(context *settings.PirContext) {
	utils.Logger.WithFields(logrus.Fields{"service": "client", "context": context}).Info("Updating context")
	PC.Context = context
}

// Generate profile given a set of parameters and stores it, if not already present. Context must be previously set
func (PC *PIRClient) GenProfile(params bfv.Parameters, paramsId string) (*settings.PIRProfile, error) {
	utils.Logger.WithFields(logrus.Fields{"service": "client", "paramsId": params}).Info("Generating profile")
	box, err := settings.NewHeBox(params)
	if err != nil {
		return nil, err
	}
	box.GenSk()
	profile := &settings.PIRProfile{
		Rlk:           box.GenRelinKey(),
		Rtks:          box.GenRtksKeys(),
		ParamsId:      paramsId,
		ContextHash:   PC.Context.Hash(),
		Box:           box,
		KnownByServer: false,
	}
	utils.Logger.WithFields(logrus.Fields{"service": "client", "paramsId": params}).Info("Generated profile")
	return profile, nil
}

// Generates a set of profile for the various leakages according to current context,
// Context must be previously set
func (PC *PIRClient) GenProfileSet() error {
	if PC.Context == nil {
		return errors.New("Need to initialize context")
	}
	ctx := PC.Context
	utils.Logger.WithFields(logrus.Fields{"service": "client"}).Info("Generating profile set")
	for contexts, _ := range PC.Pp {
		if contexts == ctx.Hash() {
			//profiles for context already created
			utils.Logger.WithFields(logrus.Fields{"service": "client"}).Warn("Profiles for context already stored")
			return nil
		}
	}
	logN := int(math.Log2(float64(ctx.N)))
	profiles := make(map[int]*settings.PIRProfile)
	var err error
	for _, leakage := range []int{messages.NONELEAKAGE, messages.STANDARDLEAKAGE, messages.HIGHLEAKAGE} {
		paramsId, params := settings.GetsParamForPIR(logN, server.DEFAULTDIMS, true, leakage != messages.NONELEAKAGE, leakage)
		profiles[leakage], err = PC.GenProfile(params, paramsId)
		if err != nil {
			return err
		}
	}
	PC.Pp[ctx.Hash()] = &settings.PIRProfileSet{
		P: profiles,
	}
	utils.Logger.WithFields(logrus.Fields{"service": "client", "contextHash": ctx.Hash()}).Info("Generated profile set")
	return nil
}

// generates query to download context
func (PC *PIRClient) ContextReqGen() *messages.PIRQuery {
	return &messages.PIRQuery{
		Q:            nil,
		Leakage:      0,
		Seed:         0,
		ClientId:     PC.Id,
		Profile:      nil,
		FetchContext: true,
	}
}

// Fetches context from ISP and sets it along new profiles
func (PC *PIRClient) RequireContext() {
	request := PC.ContextReqGen()
	answer, err := PC.SendQuery(request, PC.GrpcAddrPort)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Error fetching context")
		panic("Error fetching context: " + err.Error())
	}
	_, err = PC.ParseAnswer(answer, nil)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Error fetching context")
		PC.ResponseChan <- &InternalResponse{Error: err}
	}
	PC.ResponseChan <- &InternalResponse{}
}

/*
Given a key, generates a WPIR query
It assumes that both the querier and the server agree on the same context (i.e logN and logT params for BFV and hypercube dimentions)
key: key of the element (e.g a subset of the data items, e.g some keywords)
Set dinamically the level of information leakage from 0 (none) to 2 (max).
Currently only queries with expansion set to true and compressed set to true are supported:
This will represent the query with one ciphertext per hypercube dimention (which will be then obliviously expanded at the server)
and each ciphertext will be compressed in one polynomial instead of two
*/
func (PC *PIRClient) QueryGen(key []byte, profile *settings.PIRProfile, leakage int, weaklyPrivate, expansion, compressed bool) (*messages.PIRQuery, float64, error) {
	//new seeded prng
	ctx := PC.Context
	seed := rand.Int63n(1<<63 - 1)
	prng, err := messages.NewPRNG(seed)
	if err != nil {
		panic(err)
	}
	box := profile.Box
	box.WithEncryptor(bfv.NewPRNGEncryptor(box.Params, box.Sk).WithPRNG(prng))
	q := new(messages.PIRQuery)
	q.Leakage = leakage
	q.ClientId = PC.Id
	q.Seed = seed
	q.Profile = profile
	q.Q = new(messages.PIRQueryItemContainer)
	leakedBits := 0.0
	if !weaklyPrivate {
		if compressed {
			q.Q.Compressed, err = PC.compressedQueryGen(key, ctx.Kd, ctx.Dim, box)
		} else {
			q.Q.Expanded, err = PC.queryGen(key, *ctx, box)
		}
	} else {
		if compressed == false {
			return nil, 0, errors.New("WPIR queries are not supported without compression")
		}
		if leakage == messages.NONELEAKAGE {
			return nil, 0, errors.New("NONE leakage is supported only if not weakly private query")
		}
		s := 1.0
		if leakage == messages.STANDARDLEAKAGE {
			s = math.Floor(float64(ctx.Dim) / 2)
		}
		if leakage == messages.HIGHLEAKAGE {
			s = float64(ctx.Dim - 1)
		}

		leakedBits = (s / float64(ctx.Dim)) * math.Log2(float64(ctx.K))
		q.Q.Compressed, q.Prefix, err = PC.wpQueryGen(key, ctx.Kd, ctx.Dim, int(s), box)
	}
	keyInDb, _ := utils.MapKeyToDim(key, PC.Context.Kd, PC.Context.Dim)
	utils.Logger.WithFields(logrus.Fields{"service": "client", "key": string(key), "DB pos": keyInDb, "leak": leakage}).Info("Generated Query")
	utils.Logger.WithFields(logrus.Fields{"service": "client", "Dimentions": PC.Context.Dim, "Kd": PC.Context.Kd, "N": PC.Context.N, "hash": PC.Context.Hash()}).Debug("With Context")
	return q, leakedBits, err
}

/*
Generates no leakage query with no expansion required (high network cost)
*/
func (PC *PIRClient) queryGen(key []byte, ctx settings.PirContext, box *settings.HeBox) ([][]*messages.PIRQueryItem, error) {
	Kd, dimentions := ctx.Kd, ctx.Dim
	if box.Ecd == nil || box.Enc == nil || box.Dec == nil {
		return nil, errors.New("Client is not initialiazed with Encoder or Encryptor or Decryptor")
	}
	_, keys := utils.MapKeyToDim(key, Kd, dimentions)
	query := make([][]*messages.PIRQueryItem, dimentions)
	for i, k := range keys {
		queryOfDim := make([]*messages.PIRQueryItem, Kd)
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
			queryOfDim[d] = messages.CompressCT(c)
		}
		query[i] = queryOfDim
	}
	return query, nil
}

/*
Generates a compressed no leakage query (low network cost, expansion at server needed)
*/
func (PC *PIRClient) compressedQueryGen(key []byte, Kd, dimentions int, box *settings.HeBox) ([]*messages.PIRQueryItem, error) {
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

	query := make([]*messages.PIRQueryItem, dimentions)
	enc := box.Enc
	ecd := box.Ecd

	for i := range query {
		ct := enc.EncryptNew(utils.EncodeCoeffs(ecd, box.Params, selectors[i]))
		query[i] = messages.CompressCT(ct)
	}
	return query, nil
}

// |
// | W PIR
// v

/*
Generates a variable leakage query (expansion needed at server, low network cost)
*/
func (PC *PIRClient) wpQueryGen(key []byte, Kd, dimentions, dimToSkip int, box *settings.HeBox) ([]*messages.PIRQueryItem, string, error) {
	if box.Ecd == nil || box.Enc == nil {
		return nil, "", errors.New("Client is not initliazed with Encoder or Encryptor")
	}
	//l := int(math.Ceil(float64(PC.Context.K) / float64(box.Params.N())))
	_, keys := utils.MapKeyToDim(key, Kd, dimentions)
	selectors := make([][]uint64, dimentions-dimToSkip)

	//gen selection vectors
	for i, k := range keys[dimToSkip:] {
		selectors[i] = make([]uint64, Kd)
		selectors[i][k] = 1
	}

	query := make([]*messages.PIRQueryItem, dimentions-dimToSkip)
	enc := box.Enc
	ecd := box.Ecd

	prefix := ""
	for i := 0; i < dimToSkip; i++ {
		prefix += strconv.FormatInt(int64(keys[i]), 10) + "|"
	}
	prefix = prefix[:len(prefix)-1] //remove final |

	for i := range query {
		ct := enc.EncryptNew(utils.EncodeCoeffs(ecd, box.Params, selectors[i]))
		query[i] = messages.CompressCT(ct)
	}

	return query, prefix, nil
}

// Returns payload from DB if any,
// and error.
// It also automatically updates context with the one sent by server
// and generates a new profile set accordingly if needed
func (PC *PIRClient) ParseAnswer(answer *messages.PIRAnswer, profile *settings.PIRProfile) ([]byte, error) {
	PC.AddContext(answer.Context)
	err := PC.GenProfileSet()
	if answer.Ok {
		if answer.FetchContext {
			utils.Logger.WithFields(logrus.Fields{"service": "client", "answer": "fetch-context"}).Info("Parsing answer")
			return nil, err
		} else if answer.Answer != nil {
			utils.Logger.WithFields(logrus.Fields{"service": "client", "answer": "encrypted answer"}).Info("Parsing answer")
			data, err := PC.AnswerGet(profile, answer.Answer)
			if err != nil {
				return nil, err
			} else {
				utils.Logger.WithFields(logrus.Fields{"service": "client", "answer": string(data)}).Info("Parsed answer")
				return data, nil
			}
		}
	} else {
		utils.Logger.WithFields(logrus.Fields{"service": "client", "answer-error": answer.Error}).Info("Parsed answer with Error")
		return nil, errors.New(answer.Error)
	}
	return nil, errors.New("Could not parse Answer")
}

// Given an encrypted answers, decrypts and parses it into bytes
func (PC *PIRClient) AnswerGet(profile *settings.PIRProfile, answer []*rlwe.Ciphertext) ([]byte, error) {
	//update profile
	profile.KnownByServer = true
	utils.Logger.WithFields(logrus.Fields{"service": "client", "profile": profile, "paramsId": profile.ParamsId, "contextHash": profile.ContextHash}).Info("Decrypting answer")
	box := profile.Box
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

// Decodes bytes into a series of ICFRecords
func (PC *PIRClient) decodeICFRecords(payload []byte) ([]*server.ICFRecord, error) {
	items := bytes.Split(payload, server.ITEMSEPARATOR)
	records := make([]*server.ICFRecord, len(items))
	for i := range items {
		records[i] = new(server.ICFRecord)
		err := records[i].SuccinctDecode(items[i])
		if err != nil {
			return nil, err
		}
	}
	return records, nil
}

// GRPC
// |
// v

// Sends query to ICF via gRPC service in Python. Address is of form "ip:port"-
// Returns a PIRAnswer to parse and any gRPC or parsing error
func (PC *PIRClient) SendQuery(query *messages.PIRQuery, address string) (*messages.PIRAnswer, error) {
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(200*1024*1024), grpc.MaxCallSendMsgSize(200*1024*1024)))
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Connection error")
		log.Println(err)
		return nil, err
	}
	defer conn.Close()

	client := pb.NewProxyClient(conn)
	data, err := json.Marshal(query)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Json Encode Error")
		return nil, err
	}
	req := pb.QueryMessage{
		Query: base64.StdEncoding.EncodeToString(data),
	}
	utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "addr": address, "data": base64.StdEncoding.EncodeToString(data)[:int(utils.Min(float64(utils.MAXLEN), float64(len(base64.StdEncoding.EncodeToString(data)))))]}).Debug("Sending GRPC Query")
	resp, err := client.Query(context.Background(), &req)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Error")
		return nil, err
	}
	utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "response": logrus.Fields{"answer": resp.GetAnswer()[:int(utils.Min(float64(utils.MAXLEN), float64(len(resp.GetAnswer()))))], "error": resp.GetError()}}).Info("Received GRPC Response")
	if resp.GetError() == "" {
		answerDec, err := base64.StdEncoding.DecodeString(resp.GetAnswer())
		if err != nil {
			utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("B64 decode Error")
			return nil, err
		}
		pirAnswer := &messages.PIRAnswer{}
		err = json.Unmarshal(answerDec, pirAnswer)
		if err != nil {
			log.Println(err)
			utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Json Decode Error")
			return nil, err
		}
		utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "ok": pirAnswer.Ok, "error": pirAnswer.Error, "fetch-context": pirAnswer.FetchContext}).Info("Answer")
		return pirAnswer, err
	} else {
		return nil, errors.New("gRPC Answer Message: error= " + resp.GetError())
	}
}
