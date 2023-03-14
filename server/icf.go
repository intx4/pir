// Package implements the server side for PIR
package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"log"
	"net"
	"pir/messages"
	pb "pir/server/pb"
	"pir/settings"
	"pir/utils"
	"strings"
	"time"
)

var MAXTTL int = 3600 * 24 * 5 //5 days in s
var CACHETTL int = 3600        //1 hr in s
var FIELDSEPARATOR = ";"
var DUMMYTIMEPAD = "Z"

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
	values := strings.Split(s, FIELDSEPARATOR)
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
		if string(c) == DUMMYTIMEPAD {
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
	if time.Since(IR.MaxTTL).Seconds() > float64(MAXTTL) {
		return true
	}
	if !IR.CacheTTL.IsZero() {
		if time.Since(IR.CacheTTL).Seconds() > float64(CACHETTL) {
			return true
		}
	}
	return false
}

func (IR *ICFRecord) String() string {
	endTime := IR.EndTimestpm
	if strings.Contains(endTime, DUMMYTIMEPAD) {
		endTime = "Still valid"
	}
	return fmt.Sprintf("SUPI=%s, SUCI=%s, GUTI=%s, START TIME=%s, END TIME=%s", IR.Supi, IR.Suci, IR.FiveGGUTI, IR.StartTimestmp, endTime)
}

// Defines the ICF, with an internal PIR enabled server, a XER server
// The ICF implements a GRPC server to listen to IQF
type ICF struct {
	pb.UnimplementedInternalServerServer
	pirServer *PIRServer
	xerServer *XerServer
	grpcPort  string
}

func NewICF(xerAddr string, xerPort string, grpcPort string) (*ICF, error) {
	recordChan := make(chan *IEFRecord)
	xerServer, err := NewXerServer(xerAddr, xerPort, recordChan)
	if err != nil {
		return nil, err
	}
	pirServer, err := NewPirServer(recordChan)
	//assumption on data size = 300B
	if err != nil {
		return nil, err
	}
	return &ICF{
		pirServer: pirServer,
		xerServer: xerServer,
		grpcPort:  grpcPort,
	}, nil
}

func (I *ICF) mustEmbedUnimplementedInternalServerServer() {}

// GRPC service, entry point to WPIR protocol
func (I *ICF) Query(ctx context.Context, request *pb.InternalRequest) (*pb.InternalResponse, error) {
	pirQuery := &messages.PIRQuery{}
	pirAnswer := &messages.PIRAnswer{}
	utils.Logger.WithFields(logrus.Fields{"service": "GRPC"}).Info("Received GRPC request")
	data, err := base64.StdEncoding.DecodeString(request.Query)
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Error Decoding B64 query")
		pirAnswer = &messages.PIRAnswer{
			Answer:       nil,
			Context:      I.pirServer.GetContext(),
			Error:        settings.Base64Error + err.Error(),
			FetchContext: false,
			Ok:           false,
		}
	} else {
		err = pirQuery.UnMarshalBinary(data)
		if err != nil {
			utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Error Unmarshaling pirQuery")
			pirAnswer = &messages.PIRAnswer{
				Answer:       nil,
				Context:      I.pirServer.GetContext(),
				Error:        settings.JsonError + err.Error(),
				Ok:           false,
				FetchContext: false,
			}
		} else if pirQuery.Profile != nil {
			if I.pirServer.GetContext().Hash() == pirQuery.Profile.ContextHash {
				I.pirServer.AddProfile(pirQuery.ClientId, pirQuery.Leakage, pirQuery.Profile)
				answer, err := I.pirServer.Answer(pirQuery)
				if err != nil {
					utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Error")
					pirAnswer = &messages.PIRAnswer{
						Answer:       nil,
						Context:      I.pirServer.GetContext(),
						Error:        settings.PirError + err.Error(),
						Ok:           false,
						FetchContext: false,
					}
				} else {
					utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "answer len": len(answer)}).Info("PIR Answer computed")
					pirAnswer = &messages.PIRAnswer{
						Answer:       answer,
						Context:      I.pirServer.GetContext(),
						Error:        "",
						Ok:           true,
						FetchContext: false,
					}
				}
			} else {
				utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": settings.ContextError}).Error("Error")
				pirAnswer = &messages.PIRAnswer{
					Answer:       nil,
					Context:      I.pirServer.GetContext(),
					Error:        settings.ContextError,
					Ok:           false,
					FetchContext: false,
				}
			}
		} else {
			if pirQuery.FetchContext {
				utils.Logger.WithFields(logrus.Fields{"service": "GRPC"}).Info("Fetch Context request")
				pirAnswer = &messages.PIRAnswer{
					Answer:       nil,
					Context:      I.pirServer.GetContext(),
					Error:        "",
					Ok:           true,
					FetchContext: true,
				}
			} else {
				utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": settings.MissingProfileError}).Error("Error")
				pirAnswer = &messages.PIRAnswer{
					Answer:       nil,
					Context:      I.pirServer.GetContext(),
					Error:        settings.MissingProfileError,
					Ok:           false,
					FetchContext: false,
				}
			}
		}
	}
	data, err = pirAnswer.MarshalBinary()
	if err != nil {
		utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "error": err.Error()}).Error("Error")
		return nil, err
	}
	utils.Logger.WithFields(logrus.Fields{"service": "gRPC", "data": base64.StdEncoding.EncodeToString(data)}).Debug("Sending gRPC response")
	return &pb.InternalResponse{Answer: base64.StdEncoding.EncodeToString(data)}, nil
}

// Starts XER server to interface with IEF, PIR server and GRPC server to interface with Python pb serving IQF. Blocking
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
	listener, err := net.Listen("tcp", "127.0.0.1:"+I.grpcPort)
	if err != nil {
		utils.Logger.Error(err.Error())
		panic(err)
	}
	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(200*1024*1024),
		grpc.MaxSendMsgSize(200*1024*1024))

	pb.RegisterInternalServerServer(server, I)
	utils.Logger.WithFields(logrus.Fields{"service": "GRPC", "port": I.grpcPort}).Info("GRPC Internal server started")
	if err := server.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
		utils.Logger.Error(err.Error())
	}
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
