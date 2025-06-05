package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <datalogger-ip>")
		fmt.Println("Example: go run main.go 192.168.88.88")
		os.Exit(1)
	}

	dataloggerIP := os.Args[1]

	// Connect to the datalogger via UDP on port 58899
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:58899", dataloggerIP))
	if err != nil {
		fmt.Printf("Failed to resolve UDP address: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("✓ UDP connection established to %s:58899\n", dataloggerIP)

	// Connection stays open until you press Enter
	fmt.Println("\nPress Enter to close connection...")
	fmt.Scanln()
}
