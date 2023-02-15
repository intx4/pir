# Enabling Practical Privacy-Preserving Lawful Interception in 5G SA Core with Weakly Private Information Retrieval

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