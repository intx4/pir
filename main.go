// Main PIR application
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	pclient "pir/client"
	backend "pir/client/backend"
	"pir/messages"
	pserver "pir/server"
	"pir/utils"
	"strconv"
	"time"
)

type serverConfig struct {
	XerAddr  string `json:"xer_addr,omitempty"`
	XerPort  string `json:"xer_port,omitempty"`
	XqrAddr  string `json:"xqr_addr,omitempty"`
	XqrPort  string `json:"xqr_port,omitempty"`
	GrpcPort string `json:"grpc_port,omitempty"`
}

type clientConfig struct {
	Ip               string `json:"ip"`
	Id               string `json:"id"`
	HiqrAddr         string `json:"hiqr_addr,omitempty"`
	HiqrPort         string `json:"hiqr_port,omitempty"`
	IqfAddr          string `json:"iqf_addr,omitempty"`
	IqfPort          string `json:"iqf_port,omitempty"`
	GrpcPort         string `json:"grpc_port,omitempty"`
	InterceptionPort string `json:"interception_port"`
	WebUIPort        string `json:"web_ui_port"`
}

var MAXBUFF = 2000

func main() {

	//init logger
	utils.LogInit()

	flag.PrintDefaults()
	clientF := flag.Bool("client", false, "--client to start client application")
	serverF := flag.Bool("server", false, "--server to start server application")
	dir := flag.String("dir", "./config", "--dir file to specify directory of config file")

	flag.Parse()
	if *clientF {
		utils.Logger.Info("Starting Client application")
		conf := new(clientConfig)
		jsonFile, err := os.Open(*dir + "/client.json")
		// if we os.Open returns an error then handle it
		if err != nil {
			utils.Logger.Error(err.Error())
			os.Exit(1)
		}
		byteValue, _ := io.ReadAll(jsonFile)
		err = json.Unmarshal(byteValue, conf)
		if err != nil {
			utils.Logger.Error(err.Error())
			os.Exit(1)
		}
		requestChan := make(pclient.RequestChannel)
		responseChan := make(pclient.ResponseChannel)
		client := pclient.NewPirClient(conf.Id, "127.0.0.1"+":"+conf.GrpcPort, requestChan, responseChan)
		backend := backend.NewBackend(conf.Ip, conf.InterceptionPort, requestChan, responseChan)
		fmt.Println("Attempting connection to ISP...")
		go client.Start()
		msg := <-client.ResponseChan
		if msg.Error == nil {
			fmt.Println("Connection to ISP succeded! Context Syncronized")
		} else {
			panic("Connection to ISP failed! Could not Syncronize Context. Error: " + err.Error())
		}
		errCh := make(chan error)
		go backend.Start(errCh)

		//wait 1 seconds for errors, if no continue
		start := time.Now()
		ok := false
		for !ok {
			select {
			case err := <-errCh:
				if err != nil {
					panic(err.Error())
				}
			default:
				now := time.Since(start).Seconds()
				if now >= 1 {
					ok = true
				}
			}
		}
		fmt.Println("Backend started!")
		/*
			buff := make(chan *pclient.InternalRequest, MAXBUFF)
			cache := make(map[string]*pserver.ICFRecord)
				for true {
					request := new(pclient.InternalRequest)
					select {
					case request = <-buff: //take from buffer in any
					default: //take from stdin
						request = GetInputStdIn()
					}
					client.RequestChan <- request
					if record, stored := cache[string(request.Key)]; stored {
						utils.Logger.WithFields(logrus.Fields{"Association": record.String()}).Info("Association Record Cached")
						fmt.Println("Association Record from Cache: " + record.String())
						continue
					}
					msg = <-client.ResponseChan
					if msg.Error != nil {
						utils.Logger.WithFields(logrus.Fields{"error": msg.Error.Error()}).Error("Could not process query")
						select {
						case buff <- request: //try to put failed req in buffer
						default:
							panic("Too many failed requests!")
						}
					} else {
						found := false
						for _, record := range msg.Payload {
							utils.Logger.WithFields(logrus.Fields{"Association": record.String()}).Info("Association Record")
							if record.Suci == string(request.Key) {
								found = true
								fmt.Println("Association Record: " + record.String())
							}
							cache[record.Suci] = record
						}
						if !found {
							fmt.Println(fmt.Sprintf("Request SUCI %s was not found", string(request.Key)))
						}
					}
				}
		*/
		fmt.Println(fmt.Sprintf("Go to http://localhost:%s for API on host machine", conf.WebUIPort))
		for true {
			//serve
		}
	} else if *serverF {
		utils.Logger.Info("Starting Server application")
		fmt.Println("Starting Server application")
		conf := new(serverConfig)
		jsonFile, err := os.Open(*dir + "/server.json")
		// if we os.Open returns an error then handle it
		if err != nil {
			utils.Logger.Error(err.Error())
			os.Exit(1)
		}
		byteValue, _ := io.ReadAll(jsonFile)
		err = json.Unmarshal(byteValue, conf)
		if err != nil {
			utils.Logger.Error(err.Error())
			os.Exit(1)
		}
		server, err := pserver.NewICF(conf.XerAddr, conf.XerPort, conf.GrpcPort)
		if err != nil {
			utils.Logger.Error("Cannot start ICF " + err.Error())
			panic(err)
		}
		go server.Start()
		fmt.Println("Started ICF")
		for true { //serve
		}
	} else {
		flag.PrintDefaults()
		os.Exit(1)
	}
}

func GetInputStdIn() *pclient.InternalRequest {
	var suci string
	var text string
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("SUCI to look for: ")
	for scanner.Scan() {
		suci = scanner.Text()
		err := scanner.Err()
		if err != nil {
			utils.Logger.Error("Error reading input")
			panic(err)
		}
		for suci == "" {
			fmt.Println("SUCI to look for: ")
			suci = scanner.Text()
			err = scanner.Err()
			if err != nil {
				utils.Logger.Error("Error reading input")
				panic(err)
			}
		}
		break
	}
	scanner = bufio.NewScanner(os.Stdin)
	fmt.Println("Select leakage level between none (0) and max (2): ")
	for scanner.Scan() {
		text = scanner.Text()
		err := scanner.Err()
		if err != nil {
			utils.Logger.Error("Error reading input")
			panic(err)
		}
		leakage, err := strconv.Atoi(text)
		if (err != nil) || (leakage < messages.NONELEAKAGE || leakage > messages.HIGHLEAKAGE) {
			for (err != nil) || (leakage < messages.NONELEAKAGE || leakage > messages.HIGHLEAKAGE) {
				fmt.Println("Select leakage level between none (0) and max(2): ")
				text = scanner.Text()
				leakage, err = strconv.Atoi(text)
			}
		}
		fmt.Println("QUERY: SUCI=", suci, ", LEAKAGE=", leakage)
		utils.Logger.WithFields(logrus.Fields{"SUCI": suci, "LEAKAGE": leakage, "WP": leakage > 0}).Info("New Query: ")
		return &pclient.InternalRequest{
			Key:           []byte(suci),
			Expansion:     true,
			WeaklyPrivate: leakage > 0,
			Leakage:       leakage,
		}
	}
	return nil
}
