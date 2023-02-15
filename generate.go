package main

//go:generate protoc --go_out=client/pb --go_opt=paths=source_relative --go_grpc_out=client --go-grpc_out=paths=source_relative client/pb/client.proto
