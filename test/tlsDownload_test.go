package test

import (
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"google.golang.org/grpc/benchmark/latency"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	path = "./data/tls.csv"
)

var (
	serverAddr = "localhost:12345"
)

func TestDownload(t *testing.T) {
	testCases := []struct {
		name    string
		size    int
		entries int
	}{
		{"Test1000_25", 1000, (1 << 25)},
		{"Test1000_22", 1000, (1 << 22)},
		{"Test1000_20", 1000, (1 << 20)},
		{"Test1000_18", 1000, (1 << 18)},
		{"Test1000_16", 1000, (1 << 16)},
		{"Test1000_16", 1000, (1 << 14)},
		{"Test1000_16", 1000, (1 << 12)},
		{"Test1000_16", 1000, (1 << 10)},

		{"Test288_25", 288, (1 << 25)},
		{"Test288_22", 288, (1 << 22)},
		{"Test288_20", 288, (1 << 20)},
		{"Test288_16", 288, (1 << 16)},
		{"Test30_25", 30, (1 << 25)},
		{"Test30_22", 30, (1 << 22)},
		{"Test30_20", 30, (1 << 20)},
		{"Test30_16", 30, (1 << 16)},
	}
	csvFile := new(os.File)
	var err error
	os.Remove(path)
	csvFile, err = os.Create(path)
	if err != nil {
		t.Fatalf(err.Error())
	}

	csvW := csv.NewWriter(csvFile)

	defer csvFile.Close()

	headers := []string{"entries", "size", "time", "speed"}
	csvW.Write(headers)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create latency options
			fileSize := float64(tc.size * tc.entries)
			file := RandByteString(int(fileSize))
			for i := range DLSpeeds {
				dl := DLSpeeds[i] * 1024 //to Kbps
				latencyOpts := &latency.Network{
					Kbps: int(dl),
					MTU:  1500,
				}

				// Create server
				server := &http.Server{
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Disposition", "attachment; filename=test.csv")
						w.Header().Set("Content-Type", "application/octet-stream")
						w.Header().Set("Content-Length", strconv.FormatInt(int64(fileSize), 10))
						w.Header().Set("Connection", "close")
						w.Header().Set("Expires", "-1")
						buf := bytes.NewReader(file)
						io.Copy(w, buf)
					}),
				}

				// Start server
				ln, err := net.Listen("tcp", serverAddr)
				if err != nil {
					t.Fatalf("Error starting server: %v", err)
				}
				lnLatency := latencyOpts.Listener(ln)
				fmt.Println("Starting server TLS at...", serverAddr)
				go func() {
					err := server.ServeTLS(lnLatency, "./data/server.crt", "./data/server.key")
					if err != nil && err != http.ErrServerClosed {
						t.Fatalf(err.Error())
					} else {
						fmt.Println("Server listening")
					}
				}()

				// create a client with TLS
				client := &http.Client{
					Transport: &http.Transport{
						Dial: func(network, address string) (net.Conn, error) {
							c, err := net.Dial("tcp", serverAddr)
							if err != nil {
								return nil, err
							}
							conn, err := latencyOpts.Conn(c)
							if err != nil {
								return nil, err
							}
							return conn, nil
						},
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
					},
				}

				// download the file from the server
				fmt.Println("Client retrieving file of size (GB):", fileSize/1e9)
				time.Sleep(1 * time.Second)
				start := time.Now()
				resp, err := client.Get("https://" + serverAddr)
				if err != nil {
					log.Fatal(err)
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Fatal(err)
				}
				if len(body) < int(fileSize) {
					t.Fatalf("body if less then file")
				}
				end := time.Since(start).Seconds()
				records := fmt.Sprintf("%d, %d, %f, %f", tc.entries, tc.size, end, (dl/1024)/Mb)
				err = csvW.Write(strings.Split(records, ","))
				if err != nil {
					t.Logf(err.Error())
				}
				csvW.Flush()
				err = csvW.Error()
				if err != nil {
					t.Logf(err.Error())
				}
				log.Println(records)
				server.Close()
			}
		})
	}
}
