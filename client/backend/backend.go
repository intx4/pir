// Implements the backend server needed to interact with the web gui
package backend

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"math"
	"net/http"
	"pir/client"
	"pir/server"
	"sync"
	"time"
)
import (
	"pir/utils"
)

var TYPECAPTURE = "capture"
var TYPEASSOCIATION = "association"

var TYPESUCI = "SUCI"
var TYPEGUTI = "TMSI"
var MAXJOBS = math.MaxInt

type Interception struct {
	Type      string `json:"type,omitempty"`
	Value     string `json:"value,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

type Capture struct {
	Type      string `json:"type,omitempty"`
	Id        int    `json:"id"`
	Suci      string `json:"suci,omitempty"`
	Guti      string `json:"guti,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

type ResolveRequest struct {
	Id      int    `json:"id"`
	Type    string `json:"type"`
	Leakage int    `json:"leakage"`
}

type Association struct {
	Type           string  `json:"type"`
	Id             int     `json:"id"`
	Supi           string  `json:"supi,omitempty"`
	Suci           string  `json:"suci,omitempty"`
	Guti           string  `json:"guti,omitempty"`
	StartTimestamp string  `json:"startTimestamp,omitempty"`
	EndTimestamp   string  `json:"endTimestamp,omitempty"`
	Leakage        float64 `json:"leakage"`
	Latency        float64 `json:"latency,omitempty"`
	Error          string  `json:"error"`
}

type CaptureChannel chan *Capture
type ResolveChannel chan *ResolveRequest
type AssociationChannel chan *Association

type BackEndServer struct {
	cLock            *sync.RWMutex
	conn             *websocket.Conn
	currentId        int
	capturesCache    chan *Capture           //caches captures to be sent to frontend
	captures         map[int]*Capture        //reflects what's shown in frontend
	associations     map[int]*Association    //reflects what's shown in frontend
	captureChan      CaptureChannel          //reads captures from interceptor
	associationCache map[string]*Association //extra records already resolved
	RequestChan      client.RequestChannel   //to PIR logic
	ResponseChan     client.ResponseChannel  //from PIR logic
	Ip               string
	Port             string
}

var upgrader = websocket.Upgrader{} // use default options

func NewBackend(Ip string, Port string, reqCh client.RequestChannel, resCh client.ResponseChannel) *BackEndServer {
	return &BackEndServer{
		currentId:        1,
		cLock:            new(sync.RWMutex),
		captures:         make(map[int]*Capture),
		associations:     make(map[int]*Association),
		captureChan:      make(CaptureChannel),
		associationCache: make(map[string]*Association),
		RequestChan:      reqCh,
		ResponseChan:     resCh,
		Ip:               Ip,
		Port:             Port,
	}
}

func (BE *BackEndServer) handleResolveRequest() {
	for {
		resolveRequest := new(ResolveRequest)
		err := BE.conn.ReadJSON(resolveRequest)
		if err != nil {
			utils.Logger.WithFields(logrus.Fields{"service": "Backend", "error": err.Error()}).Error("Failed to read WebSocket message")
			break
		}
		BE.cLock.RLock()
		if item, ok := BE.captures[resolveRequest.Id]; ok {
			BE.cLock.RUnlock()
			//valid request
			utils.Logger.WithFields(logrus.Fields{"service": "Backend", "id": resolveRequest.Id, "leak": resolveRequest.Leakage, "type": resolveRequest.Type}).Info("Starting resolution")
			stored := false
			record := new(Association)
			record = nil //make a nil pointer to association
			if resolveRequest.Type == TYPESUCI {
				if record, stored = BE.associationCache[item.Suci]; stored {
					utils.Logger.WithFields(logrus.Fields{"service": "Backend", "record": (&server.ICFRecord{
						Supi:          record.Supi,
						FiveGGUTI:     record.Guti,
						StartTimestmp: record.StartTimestamp,
						EndTimestpm:   record.EndTimestamp,
						Suci:          record.Suci,
					}).String()}).Info("Association Record Cached")
				} else {
					//not cached, query
					BE.RequestChan <- &client.InternalRequest{
						Key:           []byte(item.Suci),
						Expansion:     true,
						WeaklyPrivate: resolveRequest.Leakage != 0,
						Leakage:       resolveRequest.Leakage,
					}
				}
			} else {
				if record, stored = BE.associationCache[item.Guti]; stored {
					utils.Logger.WithFields(logrus.Fields{"service": "Backend", "record": (&server.ICFRecord{
						Supi:          record.Supi,
						FiveGGUTI:     record.Guti,
						StartTimestmp: record.StartTimestamp,
						EndTimestpm:   record.EndTimestamp,
						Suci:          record.Suci,
					}).String()}).Info("Association Record Cached")
				} else {
					//not cached, query
					BE.RequestChan <- &client.InternalRequest{
						Key:           []byte(item.Guti),
						Expansion:     true,
						WeaklyPrivate: resolveRequest.Leakage != 0,
						Leakage:       resolveRequest.Leakage,
					}
				}
			}
			if !stored {
				//elaborate response from PIR client
				response := <-BE.ResponseChan
				if response.Error != nil {
					utils.Logger.WithFields(logrus.Fields{"service": "Backend", "error": response.Error.Error()}).Error("Response error from PIR logic")
					BE.conn.WriteJSON(&Association{
						Type:  TYPEASSOCIATION,
						Id:    resolveRequest.Id,
						Error: fmt.Sprintf("Error processing request, try again"),
					})
					continue
				} else {
					//look in records while caching
					found := false
					for _, r := range response.Payload {
						utils.Logger.WithFields(logrus.Fields{"Association": r.String()}).Info("New Association Record")
						if resolveRequest.Type == TYPESUCI {
							if r.Suci == item.Suci {
								found = true
								record = &Association{
									Type:           TYPEASSOCIATION,
									Id:             resolveRequest.Id,
									Supi:           r.Supi,
									Suci:           r.Suci,
									Guti:           r.FiveGGUTI,
									StartTimestamp: r.StartTimestmp,
									EndTimestamp:   r.EndTimestpm,
									Leakage:        response.Leakage,
									Latency:        response.Latency,
								}
								utils.Logger.WithFields(logrus.Fields{"Association": r.String()}).Info("Association Record Found")
							}
							BE.associationCache[r.Suci] = &Association{
								Type:           TYPEASSOCIATION,
								Id:             resolveRequest.Id,
								Supi:           r.Supi,
								Suci:           r.Suci,
								Guti:           r.FiveGGUTI,
								StartTimestamp: r.StartTimestmp,
								EndTimestamp:   r.EndTimestpm,
								Leakage:        response.Leakage,
								Latency:        response.Latency,
							}
						} else {
							if r.FiveGGUTI == item.Guti {
								found = true
								record = &Association{
									Type:           TYPEASSOCIATION,
									Supi:           r.Supi,
									Suci:           r.Suci,
									Guti:           r.FiveGGUTI,
									StartTimestamp: r.StartTimestmp,
									EndTimestamp:   r.EndTimestpm,
									Leakage:        response.Leakage,
									Latency:        response.Latency,
								}
								utils.Logger.WithFields(logrus.Fields{"Association": r.String()}).Info("Association Record Found")
							}
							BE.associationCache[r.FiveGGUTI] = &Association{
								Type:           TYPEASSOCIATION,
								Supi:           r.Supi,
								Suci:           r.Suci,
								Guti:           r.FiveGGUTI,
								StartTimestamp: r.StartTimestmp,
								EndTimestamp:   r.EndTimestpm,
								Leakage:        response.Leakage,
								Latency:        response.Latency,
							}
						}
					}
					if !found {
						if resolveRequest.Type == TYPESUCI {
							utils.Logger.WithFields(logrus.Fields{"SUCI": item.Suci}).Warn("Association Record Not Found")
							BE.conn.WriteJSON(&Association{
								Type:  TYPEASSOCIATION,
								Id:    resolveRequest.Id,
								Error: fmt.Sprintf("%s Not found", item.Suci),
							})
							continue
						} else {
							utils.Logger.WithFields(logrus.Fields{"GUTI": item.Guti}).Warn("Association Record Not Found")
							BE.conn.WriteJSON(&Association{
								Type:  TYPEASSOCIATION,
								Id:    resolveRequest.Id,
								Error: fmt.Sprintf("%s Not found", item.Guti),
							})
							continue
						}
					}
				}
			}
			//record should be not nil, either from PIR answer or cache
			if record != nil {
				record.Id = resolveRequest.Id //associate record with Id, either if from cache or fresh
				BE.associations[resolveRequest.Id] = record
				cleanRecord := new(Association)
				//cleanup end time
				*cleanRecord = *record
				if cleanRecord.EndTimestamp == "" {
					cleanRecord.EndTimestamp = "Still valid"
				}
				utils.Logger.WithFields(logrus.Fields{"service": "Backend", "id": resolveRequest.Id}).Info("Done resolution")
				BE.conn.WriteJSON(cleanRecord)
			} else {
				utils.Logger.WithFields(logrus.Fields{"service": "Backend", "id": resolveRequest.Id}).Warn("Resolution completed but no result")
			}
		} else {
			BE.cLock.RUnlock()
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// periodically fetches from cache and notify frontend
func (BE *BackEndServer) notifyFrontEnd() {
	for true {
		if BE.conn != nil {
			capture := <-BE.capturesCache
			utils.Logger.WithFields(logrus.Fields{"service": "Backend", "capture": capture.Id}).Info("Sending...")
			err := BE.conn.WriteJSON(capture)
			if err != nil {
				utils.Logger.WithFields(logrus.Fields{"service": "Backend", "error": err.Error()}).Error("Could not notify frontend")
				break
			}
			time.Sleep(500 * time.Millisecond) //super hugly for handling updates in frontend with no race condition
		}
	}
}

// Upon first connection restablish state of frontend
func (BE *BackEndServer) syncFrontend() {
	utils.Logger.WithFields(logrus.Fields{"service": "Backend"}).Info("Sync frontend...")
	for _, capture := range BE.captures {
		BE.conn.WriteJSON(capture)
		time.Sleep(100 * time.Millisecond)
	}
	for _, association := range BE.associations {
		cleanRecord := new(Association)
		//cleanup end time
		*cleanRecord = *association
		if cleanRecord.EndTimestamp == "" {
			cleanRecord.EndTimestamp = "Still valid"
		}
		BE.conn.WriteJSON(cleanRecord)
		time.Sleep(100 * time.Millisecond)
	}
}

// start BE (blocking). Provide a channel to read error state
func (BE *BackEndServer) Start(errCh chan error) {
	http.HandleFunc("/api/intercept", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			w.WriteHeader(405)
			w.Write([]byte("Not Allowed"))
		case "POST":
			utils.Logger.WithFields(logrus.Fields{"service": "Backend"}).Info("Intercept end-point received POST")
			interception := new(Interception)
			buff := make([]byte, r.ContentLength)
			r.Body.Read(buff)
			err := json.Unmarshal(buff, interception)
			if err != nil {
				utils.Logger.WithFields(logrus.Fields{"service": "Backend", "error": err.Error()}).Error("Error unmarshaling interception")
				w.WriteHeader(500)
				w.Write([]byte("Error unmarshaling interception"))
			} else {
				BE.cLock.Lock()
				utils.Logger.WithFields(logrus.Fields{"service": "Backend", "capture": BE.currentId}).Info("Received capture")
				capture := &Capture{
					Type:      TYPECAPTURE,
					Id:        BE.currentId,
					Timestamp: interception.Timestamp,
				}
				if interception.Type == TYPESUCI {
					capture.Suci = interception.Value
					capture.Guti = "-"
				} else if interception.Type == TYPEGUTI {
					capture.Guti = interception.Value
					capture.Suci = "-"
				} else {
					utils.Logger.WithFields(logrus.Fields{"service": "Backend", "error": fmt.Sprintf("Not a valid capture type: %s", interception.Type)}).Error("Invalid capture")
					w.WriteHeader(400)
					w.Write([]byte(fmt.Sprintf("Not a valid capture type: %s", interception.Type)))
				}
				BE.currentId++
				//record
				BE.captures[capture.Id] = capture
				BE.cLock.Unlock()
				w.WriteHeader(200)
				w.Write([]byte("ok"))
				BE.capturesCache <- capture
			}
		}
	})
	http.HandleFunc("/api/subscribe", func(w http.ResponseWriter, r *http.Request) {
		// Upgrade upgrades the HTTP server connection to the WebSocket protocol.
		upgrader.CheckOrigin = func(r *http.Request) bool { return true } //needed otherwise it gets angry :(
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			utils.Logger.WithFields(logrus.Fields{"service": "Backend", "error": err.Error()}).Error("Failed to upgrade HTTP to WebSocket")
			panic(err)
		}
		BE.conn = conn
		utils.Logger.WithFields(logrus.Fields{"service": "Backend"}).Info("WebSocket connection ok")
		//connection estalbished -> sync then notify frontend
		BE.syncFrontend()
		go BE.notifyFrontEnd()
		//serve resolve request
		BE.handleResolveRequest()
	})
	go func(errCh chan error) {
		utils.Logger.WithFields(logrus.Fields{"service": "Backend", "addr": BE.Ip, "port": BE.Port}).Info("Listening...")
		errCh <- http.ListenAndServe(BE.Ip+":"+BE.Port, nil)
	}(errCh)
	for true {
		//serve
	}
}
