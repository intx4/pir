# Partition based Weakly Private Information Retrieval based on Sparse-MulPIR
## THIS BRANCH
This branch contains the vanilla implementation of a WPIR scheme based on [MulPIR](https://eprint.iacr.org/2019/1483) used for testing of the underlying crypto protocol
and benchmarking. This branch implements a generic PIR client and server that can be used for testing and/or can be further modify to suite new use-cases. This version supports the indexed version of the scheme (no keywords)
We also provide an application of this PIR implementation for Practical and Private Lawful Interception in 5G core as part of the ```P3LI5``` project in the ```master``` branch.
### RUNNING
A test-suite is available in ```/test``` for testing the protocol (no network communication involved) in ```client_test.go```.
## DOCUMENTATION
```./help.sh``` to spawn documentation on your browser.
## ENVIRONMENT VARIABLES
Before running, set the following:
```
export PKG_CONFIG_PATH=<path_to>/pir/pkg-config/python3-embed.pc
export PYASN_DIR=<path_to>/pir/server
export PIR_LOG=<path_to>/pir/var/log/pir.log
```

## GRPC

### Go

-   Install protoc:
```
$ go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
$ go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
```
-  Update PATH:
```
$ export PATH="$PATH:$(go env GOPATH)/bin"
```
- Run protoc:
```
protoc --go_out=./client --go_opt=paths=source_relative --go-grpc_out=./client --go-grpc_opt=paths=source_relative ./client/client.proto
```
rename the ```client/client``` folder into ```client/pb```

## BUILDING
- **Download Go v19.3.1 [here](https://go.dev/doc/install):**
``` 
wget -c -q https://golang.org/dl/go1.19.3.linux-amd64.tar.gz
```
- Set ``` export PKG_CONFIG_PATH=<path_to>/pir/pkg-config/python3-embed.pc/```
- ```go build``` inside /pir