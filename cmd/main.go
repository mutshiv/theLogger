package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

func connectToLogger(address string) (*net.Conn, error) {
	conn, err := net.Dial("tcp", address)
	return &conn, err
}

func readFromLogger(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	return strings.TrimSpace(response), err
}

func writeToLogger(conn net.Conn, command string) error {
	_, err := conn.Write([]byte(command + "\n"))
	return err
}

func main() {
    conn, _ := net.Dial("tcp", "192.168.88.96:8080")
    defer conn.Close()
    
    writeToLogger(conn, "READ_ALL")
    response, _ := readFromLogger(conn)
    fmt.Println("Response:", response)
}
