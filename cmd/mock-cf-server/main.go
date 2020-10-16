package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/hashicorp/vault-plugin-auth-cf/testing/cf"
)

func main() {
	server := cf.MockServer(true)
	defer server.Close()
	fmt.Println("running at " + server.URL)
	fmt.Println("username is " + cf.AuthUsername)
	fmt.Println("password is " + cf.AuthPassword)
	fmt.Println("client id is " + cf.AuthClientID)
	fmt.Println("client secret is " + cf.AuthClientSecrete)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
