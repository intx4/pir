package pir

//go:generate protoc --go_out=plugins=grpc:client --go_opt=paths=source_relative client/client.proto
