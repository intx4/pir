package server

import (
	"testing"
)

var LOCAL = true

func test_XER(t *testing.T, addr string, port string) {
	testXER(addr, port)
}
func TestXer(t *testing.T) {
	testCases := []struct {
		name string
		addr string
		port string
	}{
		{"LOCAL", "127.0.0.1", "60021"},
		{"DOCKER", "172.17.0.1", "60021"},
	}
	if LOCAL {
		t.Run(testCases[0].name, func(t *testing.T) {
			test_XER(t, testCases[0].addr, testCases[0].port)
		})
	} else {
		t.Run(testCases[1].name, func(t *testing.T) {
			test_XER(t, testCases[1].addr, testCases[1].port)
		})
	}
}
