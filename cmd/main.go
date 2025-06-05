package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <datalogger-ip>")
		os.Exit(1)
	}

	dataloggerIP := os.Args[1]

	// Connect via UDP to port 58899
	udpAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:58899", dataloggerIP))
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("Connected to datalogger via UDP")

	// Try different query commands
	commands := []string{
		"query",
		"status",
		"info",
		"get>data;",
		"{\"cmd\":\"status\"}",
	}

	for _, cmd := range commands {
		fmt.Printf("\nSending: %s\n", cmd)
		conn.Write([]byte(cmd))

		// Read response
		buffer := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := conn.ReadFromUDP(buffer)

		if err == nil && n > 0 {
			fmt.Printf("Response: %s\n", string(buffer[:n]))
		} else {
			fmt.Println("No response")
		}
	}
}
