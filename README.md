# Enabling Practical Privacy-Preserving Lawful Interception in 5G SA Core with Lattice-Based Weakly Private Information Retrieval

## THIS BRANCH
This branch contains an implementation of [Sparse-MulPIR](https://eprint.iacr.org/2019/1483) used for private Lawful Interception PoC in 5G Core.
The code is used in deployment inside a Docker container and is part of the ```P3LI5``` project:
- [P3LI5](https://github.com/intx4/P3LI5)
- [minimal PoC for Private LI infrastructure in Python: pyli5](https://github.com/intx4/pyli5)

A standalone implementation can be found in the ```vanilla``` branch, which is just provides implementation of PIR client and server for generic applications. It also provides a test-suite for benchmarking.

### RUNNING
run ```pir --help``` to see how to use the binary. **DISCLAIMER: the binary relies on some configuration parameters and environment variables
which are normally set automatically during Docker deployment. Please look at [dockerized open5gs](https://github.com/intx4/P3LI5) ```/lea``` and ```/icf``` and related DockerFile for more information.**
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
We already provide the Go bindings for GRPC.
This is how they were generated (for reference):
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
