package backend

//Test backend in host machine with npm start for frontend
import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"pir/client"
	Server "pir/server"
	"testing"
	"time"
)

// Test the GUI on local machine
func TestBackend(t *testing.T) {
	reqCh := make(client.RequestChannel)
	resCh := make(client.ResponseChannel)
	be := NewBackend("127.0.0.1", "8484", reqCh, resCh)
	errCh := make(chan error)
	go be.Start(errCh)
	//wait 1 seconds for errors, if no continue
	start := time.Now()
	ok := false
	for !ok {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf(err.Error())
			}
		default:
			now := time.Since(start).Seconds()
			if now >= 1 {
				ok = true
			}
		}
	}
	go mockInterceptor()
	rand.Seed(231)
	for true {
		<-reqCh
		resCh <- &client.InternalResponse{
			Payload: []*Server.ICFRecord{&Server.ICFRecord{
				Supi:          "supi0",
				FiveGGUTI:     "guti0",
				StartTimestmp: time.Now().String(),
				EndTimestpm:   time.Now().Add(45 * time.Hour).String(),
				Suci:          "suci0",
			},
				&Server.ICFRecord{
					Supi:          "supi2",
					FiveGGUTI:     "guti2",
					StartTimestmp: time.Now().String(),
					EndTimestpm:   time.Now().Add(45 * time.Hour).String(),
					Suci:          "suci2",
				},
				&Server.ICFRecord{
					Supi:          "supi1",
					FiveGGUTI:     "guti1",
					StartTimestmp: time.Now().String(),
					EndTimestpm:   time.Now().Add(45 * time.Hour).String(),
					Suci:          "suci1",
				},
				&Server.ICFRecord{
					Supi:          "supi3",
					FiveGGUTI:     "guti3",
					StartTimestmp: time.Now().String(),
					EndTimestpm:   time.Now().Add(45 * time.Hour).String(),
					Suci:          "suci3",
				},
				&Server.ICFRecord{
					Supi:          "supi4",
					FiveGGUTI:     "guti4",
					StartTimestmp: time.Now().String(),
					EndTimestpm:   time.Now().Add(45 * time.Hour).String(),
					Suci:          "suci4",
				},
			},
			Leakage: rand.Float64(),
			Latency: float64(rand.Int63n(10)),
			Error:   nil,
		}
	}
}

func mockInterceptor() {
	captures := []*Interception{
		&Interception{
			Value:     "suci0",
			Type:      "SUCI",
			Timestamp: time.Now().String(),
		},
		&Interception{
			Value:     "suci1",
			Type:      "SUCI",
			Timestamp: time.Now().String(),
		},
		&Interception{
			Value:     "suci2",
			Type:      "SUCI",
			Timestamp: time.Now().String(),
		},
		&Interception{
			Value:     "suci3",
			Type:      "SUCI",
			Timestamp: time.Now().String(),
		},
		&Interception{
			Value:     "suci4",
			Type:      "SUCI",
			Timestamp: time.Now().String(),
		},
		&Interception{
			Value:     "suci5",
			Type:      "SUCI",
			Timestamp: time.Now().String(),
		},
		&Interception{
			Value:     "suci6",
			Type:      "SUCI",
			Timestamp: time.Now().String(),
		},
		&Interception{
			Value:     "suci7",
			Type:      "SUCI",
			Timestamp: time.Now().String(),
		},
		&Interception{
			Value:     "suci8",
			Type:      "SUCI",
			Timestamp: time.Now().String(),
		},
	}
	log.Println("Starting fake interceptor")
	for _, c := range captures {
		payload, err := json.Marshal(c)
		if err != nil {
			panic(err.Error())
		}
		body := bytes.NewReader(payload)
		resp, err := http.Post("http://127.0.0.1:8484/api/intercept", "application/json", body)
		if err != nil {
			log.Fatalf("An Error Occured %v", err)
		}
		defer resp.Body.Close()
		//Read the response body
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalln(err)
		}
		sb := string(respBody)
		log.Printf(sb)
		time.Sleep(1)
	}
}
