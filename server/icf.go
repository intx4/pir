package server

// //export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig/python3-embed.pc
// #cgo pkg-config: python3-embed
// #include <Python.h>
import "C"
import (
	"fmt"
	"io/ioutil"
	"log"
)

func readBytesFromFile(filepath string) ([]byte, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Wrapper for testing needed for cgo
func testXER() {
	recordChan := make(chan *IEFRecord)
	server, err := NewXerServer("172.17.0.1", "60021", recordChan)
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
