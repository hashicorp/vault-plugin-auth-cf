package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/hashicorp/vault-plugin-auth-pcf/testing/pcf"
)

func main() {
	server := pcf.MockServer(true)
	defer server.Close()
	fmt.Println("running at " + server.URL)
	fmt.Println("username is " + pcf.AuthUsername)
	fmt.Println("password is " + pcf.AuthPassword)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
