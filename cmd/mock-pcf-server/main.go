package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/hashicorp/vault-plugin-auth-pcf/testdata/pcf-api"
)

func main() {
	server := api.MockServer(true)
	defer server.Close()
	fmt.Println("running at " + server.URL)
	fmt.Println("username is " + api.AuthUsername)
	fmt.Println("password is " + api.AuthPassword)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
