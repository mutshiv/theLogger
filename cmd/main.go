package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <datalogger-ip> <your-local-ip>")
		fmt.Println("Example: go run main.go 192.168.88.88 192.168.88.92")
		os.Exit(1)
	}

	dataloggerIP := os.Args[1]
	localIP := os.Args[2]

	// Step 1: Create TCP listener
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:8899", localIP))
	if err != nil {
		fmt.Printf("Failed to create listener: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("Listening on %s:8899\n", localIP)

	// Step 2: Send UDP command to datalogger
	udpAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:58899", dataloggerIP))
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Printf("Failed to connect UDP: %v\n", err)
		os.Exit(1)
	}

	command := fmt.Sprintf("set>server=%s:8899;", localIP)
	udpConn.Write([]byte(command))
	udpConn.Close()

	fmt.Printf("Sent command: %s\n", command)
	fmt.Println("Waiting for datalogger to connect...")

	// Step 3: Accept connection
	conn, err := listener.Accept()
	if err != nil {
		fmt.Printf("Failed to accept connection: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("✓ Datalogger connected from: %s\n", conn.RemoteAddr())

	// Keep connection open
	fmt.Println("\nPress Enter to close...")
	fmt.Scanln()
}
