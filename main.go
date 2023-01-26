package pir

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	pclient "pir/client"
	pserver "pir/server"
	"pir/utils"
	"strconv"
)

func main() {
	flag.PrintDefaults()
	clientF := flag.Bool("client", false, "--client to start client application")
	serverF := flag.Bool("server", false, "--server to start server application")
	dir := flag.String("dir", ".", "--dir file to specify directory of config file")

	flag.Parse()
	if *clientF {
		*dir = ""
		requestChan := make(chan *pclient.PIRRequest)
		responseChan := make(chan []byte)
		client := pclient.NewPirClient("CYD", "127.0.0.1", requestChan, responseChan)
		go client.Start()
		for true {
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("SUCI to look for: ")
			suci, _ := reader.ReadString('\n')
			fmt.Println("Select leakage level between none (0) and max(2): ")
			text, _ := reader.ReadString('\n')
			leakage, err := strconv.Atoi(text)
			if (err != nil) || (leakage < NONELEAKAGE || leakage > HIGHLEAKAGE) {
				for (err != nil) || (leakage < NONELEAKAGE || leakage > HIGHLEAKAGE) {
					text, _ := reader.ReadString('\n')
					leakage, err = strconv.Atoi(text)
				}
			}
			fmt.Println("QUERY: SUCI=", suci, " , LEAKAGE=", leakage)
			client.RequestChan <- &pclient.PIRRequest{
				Key:           []byte(suci),
				Expansion:     true,
				WeaklyPrivate: leakage > 0,
				Leakage:       leakage,
			}
		}
	} else if *serverF {
		*dir = ""
		server, err := pserver.NewICF("127.0.0.1", "60021")
		if err != nil {
			utils.Logger.Error("Cannot start ICF " + err.Error())
			panic(err)
		}
		server.Start()
	} else {
		flag.PrintDefaults()
		os.Exit(1)
	}
}
