package client

import "testing"

// needs a grpc server listening in local
func TestGRPC(t *testing.T) {
	client := NewPirClient("1", "127.0.0.1:48888", nil, nil)
	client.Start()
}
