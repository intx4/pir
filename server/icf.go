package server

// //export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig/python3-embed.pc
// #cgo pkg-config: python3-embed
// #include <Python.h>
import "C"
import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"google.golang.org/grpc"
	"log"
	"net"
	"pir"
	pb "pir/server/pb"
	"pir/settings"
	"pir/utils"
	"strings"
	"time"
)

var MAXTTL = 3600 * 24 * 5.0 //5 days
var CACHETTL = 3600.0        //1 hr

type ICFRecord struct {
	pirDBItem
	Supi          string            `json:"supi,omitempty"`
	FiveGGUTI     string            `json:"fivegguti,omitempty"`
	StartTimestmp string            `json:"starttimestmp,omitempty"`
	EndTimestpm   string            `json:"endtimestmp,omitempty"`
	Tai           string            `json:"tai,omitempty"`
	Ncgi          map[string]string `json:"ncgi,omitempty"`
	NcgiTime      string            `json:"ncgi_time,omitempty"`
	Suci          string            `json:"suci,omitempty"`
	Pei           string            `json:"pei,omitempty"`
	ListOfTai     []string          `json:"list_of_tai,omitempty"`
	CacheTTL      time.Time         //cache TTL for regular entries
	MaxTTL        time.Time         //max TTL after entry has been deassociated
}

// Succinct encoding of ICFRecord (only SUPI,SUCI,GUTI,TIME(S))
func (IR *ICFRecord) SuccinctEncode() []byte {
	var payload string
	payload += IR.Supi
	payload += ";"
	payload += IR.Suci
	payload += ";"
	payload += IR.FiveGGUTI
	payload += ";"
	payload += IR.StartTimestmp
	payload += ";"
	if IR.EndTimestpm == "" {
		for i := 0; i < len(IR.StartTimestmp); i++ {
			payload += "Z"
		}
	} else {
		payload += IR.EndTimestpm
	}
	return []byte(payload)
}

func (IR *ICFRecord) SuccinctDecode(payload []byte) error {
	s := string(payload)
	values := strings.Split(s, ";")
	if len(values) != 5 {
		return errors.New("Wrong Succinct Encoding")
	}
	IR.Supi = values[0]
	IR.Suci = values[1]
	IR.FiveGGUTI = values[2]
	IR.StartTimestmp = values[3]
	endTime := values[4]
	notSet := false
	for _, c := range endTime {
		if string(c) == "Z" {
			notSet = true
			break
		}
	}
	if notSet {
		IR.EndTimestpm = ""
	} else {
		IR.EndTimestpm = endTime
	}
	return nil
}

// takes interface that must be an IEFAssoc or DEAssoc record, returns true if the event is related to this record (by checking supi and guti)
func (IR *ICFRecord) Match(v interface{}) bool {
	switch v.(type) {
	case *IEFAssociationRecord:
		event := v.(*IEFAssociationRecord)
		if event.Supi == IR.Supi && event.FiveGGUTI == event.FiveGGUTI {
			return true
		} else {
			return false
		}
	case *IEFDeassociationRecord:
		event := v.(*IEFDeassociationRecord)
		if event.Supi == IR.Supi && event.FiveGGUTI == event.FiveGGUTI {
			return true
		} else {
			return false
		}
	default:
		return false
	}
}

func (IR *ICFRecord) IsExpired() bool {
	if time.Since(IR.MaxTTL).Seconds() > MAXTTL {
		return true
	}
	if !IR.CacheTTL.IsZero() {
		if time.Since(IR.CacheTTL).Seconds() > CACHETTL {
			return true
		}
	}
	return false
}

/*
type ICFCacheEntry struct {
	Current  *ICFRecord
	Previous *ICFRecord
}

func NewICFCacheEntry() *ICFCacheEntry {
	return &ICFCacheEntry{
		Current:  nil,
		Previous: nil,
	}
}

// Currently active association is marked as previously active, and new one is registered as current
func (CE *ICFCacheEntry) NewAssociation(record *IEFAssociationRecord) int {
	added := 0
	if CE.Current != nil {
		if CE.Previous == nil {
			CE.Previous = new(ICFRecord)
			added++
			CE.Previous.MaxTTL = time.Now()
		}
		*CE.Previous = *CE.Current
	}
	if CE.Previous != nil {
		CE.Previous.EndTimestpm = record.Timestmp
		CE.Previous.CacheTTL = time.Now()
	}
	if CE.Current == nil {
		CE.Current = new(ICFRecord)
		added++
		CE.Current.MaxTTL = time.Now()
	}
	CE.Current.Supi = record.Supi
	CE.Current.Suci = record.Suci
	CE.Current.FiveGGUTI = record.FiveGGUTI
	CE.Current.StartTimestmp = record.Timestmp
	CE.Current.Tai = record.Tai
	CE.Current.Ncgi = record.Ncgi
	CE.Current.NcgiTime = record.NcgiTime
	CE.Current.Pei = record.Pei
	CE.Current.ListOfTai = record.ListOfTai
	return added
}

// IEFDeassociation event is received : currently active is marked as deassociated
func (CE *ICFCacheEntry) NewDeassociation(record *IEFDeassociationRecord) {
	if CE.Current != nil {
		if CE.Current.FiveGGUTI == record.FiveGGUTI {
			if CE.Previous == nil {
				CE.Previous = new(ICFRecord)
				CE.Previous.MaxTTL = time.Now()
			}
			*CE.Previous = *CE.Current
			CE.Previous.EndTimestpm = record.Timestmp
			CE.Previous.CacheTTL = time.Now()
			CE.Current = nil
		}
	} else if CE.Previous != nil {
		if CE.Previous.FiveGGUTI == record.FiveGGUTI {
			CE.Previous.Supi = record.Supi
			CE.Previous.FiveGGUTI = record.FiveGGUTI
			CE.Previous.Ncgi = record.Ncgi
			CE.Previous.NcgiTime = record.NcgiTime
			CE.Previous.EndTimestpm = record.Timestmp
		}
	}
}

type ICFCache struct {
	lock *sync.RWMutex
	Db   map[string]*ICFCacheEntry
	Size int //num of records
}

func NewICFCache() *ICFCache {
	return &ICFCache{
		lock: new(sync.RWMutex),
		Db:   make(map[string]*ICFCacheEntry),
	}
}

func (IC *ICFCache) NewRecord(record *IEFRecord) {
	IC.lock.Lock()
	defer IC.lock.Unlock()
	if record.Assoc != nil {
		if entry, ok := IC.Db[record.Assoc.Supi]; ok {
			IC.Size += entry.NewAssociation(record.Assoc)
		} else {
			entry = NewICFCacheEntry()
			IC.Size += entry.NewAssociation(record.Assoc)
		}
	} else if record.DeAssoc != nil {
		if entry, ok := IC.Db[record.DeAssoc.Supi]; ok {
			entry.NewDeassociation(record.DeAssoc)
		}
	}
}

// Sweap cache every ttl seconds
func (IC *ICFCache) Sweap(ttl float64) {
	for true {
		IC.lock.Lock()
		var expired []string
		for k, v := range IC.Db {
			if ttl == MAXTTL {
				if v.Current != nil {
					if time.Since(v.Current.MaxTTL).Seconds() >= MAXTTL {
						v.Current = nil
						IC.Size--
					}
				}
				if v.Previous != nil {
					if time.Since(v.Previous.MaxTTL).Seconds() >= MAXTTL {
						v.Previous = nil
						IC.Size--
					}
				}
			} else if ttl == CACHETTL {
				//looks for deassociated events
				if v.Previous != nil {
					if time.Since(v.Previous.CacheTTL).Seconds() >= CACHETTL {
						v.Previous = nil
						IC.Size--
					}
				}
			}
			if v.Current == nil && v.Previous == nil {
				expired = append(expired, k)
			}
		}
		for _, k := range expired {
			delete(IC.Db, k)
		}
		time.Sleep(3600 * time.Second)
	}
}

// Takes a snapshot of current cache state
func (IC *ICFCache) TakeSnapshot(byGUTI bool, bySUCI bool) map[string][]byte {
	IC.lock.RLock()
	defer IC.lock.RUnlock()

	db := make(map[string][]byte)
	for _, v := range IC.Db {
		if v.Current != nil {
			if bySUCI {
				if _, ok := db[v.Current.Suci]; !ok {
					db[v.Current.Suci] = v.Current.SuccinctEncode()
				} else {
					db[v.Current.Suci] = append(db[v.Current.Suci], []byte(";;")...)
					db[v.Current.Suci] = append(db[v.Current.Suci], v.Current.SuccinctEncode()...)
				}
			} else if byGUTI {
				if _, ok := db[v.Current.FiveGGUTI]; !ok {
					db[v.Current.FiveGGUTI] = v.Current.SuccinctEncode()
				} else {
					db[v.Current.FiveGGUTI] = append(db[v.Current.FiveGGUTI], []byte(";;")...)
					db[v.Current.FiveGGUTI] = append(db[v.Current.FiveGGUTI], v.Current.SuccinctEncode()...)
				}
			}
		}
		if v.Previous != nil {
			if bySUCI {
				if _, ok := db[v.Previous.Suci]; !ok {
					db[v.Previous.Suci] = v.Previous.SuccinctEncode()
				} else {
					db[v.Previous.Suci] = append(db[v.Previous.Suci], []byte(";;")...)
					db[v.Previous.Suci] = append(db[v.Previous.Suci], v.Previous.SuccinctEncode()...)
				}
			} else if byGUTI {
				if _, ok := db[v.Previous.FiveGGUTI]; !ok {
					db[v.Previous.FiveGGUTI] = v.Previous.SuccinctEncode()
				} else {
					db[v.Previous.FiveGGUTI] = append(db[v.Previous.FiveGGUTI], []byte(";;")...)
					db[v.Previous.FiveGGUTI] = append(db[v.Previous.FiveGGUTI], v.Previous.SuccinctEncode()...)
				}
			}
		}
	}
	return db
}
*/

type ICF struct {
	pb.UnimplementedInternalServerServer
	pirServer *PIRServer
	xerServer *XerServer
	//cache        *ICFCache
}

func NewICF(xerAddr string, xerPort string) (*ICF, error) {
	recordChan := make(chan *IEFRecord)
	xerServer, err := NewXerServer(xerAddr, xerPort, recordChan)
	if err != nil {
		return nil, err
	}
	params, _ := bfv.NewParametersFromLiteral(settings.DEFAULTPARAMS)
	pirServer, err := NewPirServer(recordChan, params)
	//assumption on data size = 300B
	if err != nil {
		return nil, err
	}
	return &ICF{
		pirServer: pirServer,
		xerServer: xerServer,
	}, nil
}

func (I *ICF) mustEmbedUnimplementedInternalServerServer() {}

func (I *ICF) Query(ctx context.Context, request *pb.InternalRequest) (*pb.InternalResponse, error) {
	pirQuery := &pir.PIRQuery{}
	pirAnswer := &pir.PIRAnswer{}
	utils.Logger.WithFields(logrus.Fields{"service": "GRPC"}).Info("Received GRPC request")
	data, err := base64.StdEncoding.DecodeString(request.Query)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Error")
		pirAnswer = &pir.PIRAnswer{
			Answer:  nil,
			Context: I.pirServer.GetContext(),
			Error:   settings.Base64Error + err.Error(),
			Ok:      false,
			Params:  I.pirServer.Params.ParametersLiteral(),
		}
	} else {
		err = json.Unmarshal(data, pirQuery)
		if err != nil {
			utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Error")
			pirAnswer = &pir.PIRAnswer{
				Answer:  nil,
				Context: I.pirServer.GetContext(),
				Error:   settings.JsonError + err.Error(),
				Ok:      false,
				Params:  I.pirServer.Params.ParametersLiteral(),
			}
		}
		if pirQuery.Profile != nil {
			if I.pirServer.GetContext().K == pirQuery.Profile.Context.K &&
				I.pirServer.GetContext().Dim == pirQuery.Profile.Context.Dim &&
				I.pirServer.GetContext().N == pirQuery.Profile.Context.N &&
				I.pirServer.GetContext().Kd == pirQuery.Profile.Context.Kd {
				I.pirServer.AddProfile(pirQuery.ClientId, pirQuery.Profile)
				answer, err := I.pirServer.Answer(pirQuery)
				if err != nil {
					utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Error")
					pirAnswer = &pir.PIRAnswer{
						Answer:  nil,
						Context: I.pirServer.GetContext(),
						Error:   settings.PirError + err.Error(),
						Ok:      false,
						Params:  I.pirServer.Params.ParametersLiteral(),
					}
				} else {
					utils.Logger.WithFields(logrus.Fields{"service": "GRPC"}).Info("PIR Answer computed")
					pirAnswer = &pir.PIRAnswer{
						Answer:  answer,
						Context: I.pirServer.GetContext(),
						Error:   "",
						Ok:      true,
						Params:  I.pirServer.Params.ParametersLiteral(),
					}
				}
			} else {
				utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": settings.ContextError}).Error("Error")
				pirAnswer = &pir.PIRAnswer{
					Answer:  nil,
					Context: I.pirServer.GetContext(),
					Error:   settings.ContextError,
					Ok:      false,
					Params:  I.pirServer.Params.ParametersLiteral(),
				}
			}
		} else {
			if pirQuery.FetchContext {
				utils.Logger.WithFields(logrus.Fields{"service": "GRPC"}).Info("Fetch Context request")
				pirAnswer = &pir.PIRAnswer{
					Answer:  nil,
					Context: I.pirServer.GetContext(),
					Error:   "",
					Ok:      true,
					Params:  I.pirServer.Params.ParametersLiteral(),
				}
			} else {
				utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": settings.MissingProfileError}).Error("Error")
				pirAnswer = &pir.PIRAnswer{
					Answer:  nil,
					Context: I.pirServer.GetContext(),
					Error:   settings.MissingProfileError,
					Ok:      false,
					Params:  I.pirServer.Params.ParametersLiteral(),
				}
			}
		}
	}
	data, err = json.Marshal(pirAnswer)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Error")
		return nil, err
	}
	return &pb.InternalResponse{Answer: base64.StdEncoding.EncodeToString(data)}, nil
}

// Starts XER server to interface with IEF and GRPC server to interface with Python client serving IQF. Blocking
func (I *ICF) Start() {
	go func() {
		err := I.xerServer.Start()
		if err != nil {
			panic(err)
		}
	}()
	go func() {
		I.pirServer.Start()
	}()
	listener, err := net.Listen("tcp", ":48888")
	if err != nil {
		panic(err)
	}
	server := grpc.NewServer()
	pb.RegisterInternalServerServer(server, I)
	if err := server.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
		utils.Logger.Error(err.Error())
	}
	utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "port": "48888"}).Info("GRPC Internal server started")
}

// Wrapper for testing needed for cgo
func testXER(addr string, port string) {
	recordChan := make(chan *IEFRecord)
	//server, err := NewXerServer("172.17.0.1", "60021", recordChan)
	server, err := NewXerServer(addr, port, recordChan)
	if err != nil {
		log.Fatal(err.Error())
	}
	go func() {
		err = server.Start()
		if err != nil {
			log.Fatal(err)
		}
	}()
	log.Printf("Listening...")
	for true {
		record := <-recordChan
		if record.Assoc != nil {
			fmt.Println(record.Assoc.Supi)
		} else if record.DeAssoc != nil {
			fmt.Println(record.DeAssoc.Supi)
		}
	}
	server.Stop()
}
