package cf

import (
	"net"
	"testing"
)

func TestMatchesIPAddr(t *testing.T) {
	certIP := net.ParseIP("10.255.181.105")
	if !matchesIPAddress("10.255.181.105/32", certIP) {
		t.Fatal("should match")
	}
	if !matchesIPAddress("10.255.181.105", certIP) {
		t.Fatal("should match")
	}
	if matchesIPAddress("127.0.0.1/32", certIP) {
		t.Fatal("shouldn't match")
	}
	if matchesIPAddress("127.0.0.1", certIP) {
		t.Fatal("shouldn't match")
	}
	if matchesIPAddress("", certIP) {
		t.Fatal("shouldn't match")
	}
}

func TestMeetsBoundConstraints(t *testing.T) {
	if !meetsBoundConstraints("fizz", []string{"fizz", "buzz"}) {
		t.Fatal("should meet constraints")
	}
	if !meetsBoundConstraints("fizz", []string{}) {
		t.Fatal("should meet constraints")
	}
	if meetsBoundConstraints("foo", []string{"fizz", "buzz"}) {
		t.Fatal("shouldn't meet constraints")
	}
	if meetsBoundConstraints("", []string{"fizz", "buzz"}) {
		t.Fatal("shouldn't meet constraints")
	}
}
