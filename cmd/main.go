package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <datalogger-ip> <your-local-ip>")
		fmt.Println("Example: go run main.go 192.168.88.88 192.168.88.92")
		os.Exit(1)
	}

	dataloggerIP := os.Args[1]
	localIP := os.Args[2]

	fmt.Printf("Local IP: %s\n", localIP)
	fmt.Printf("Datalogger IP: %s\n", dataloggerIP)

	// Step 1: Create TCP listener on port 8899
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:8899", localIP))
	if err != nil {
		fmt.Printf("Failed to create TCP listener: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("TCP listener created on %s:8899\n", localIP)

	// Step 2: Send UDP command to datalogger to connect to us
	udpAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:58899", dataloggerIP))
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Printf("Failed to connect UDP: %v\n", err)
		os.Exit(1)
	}

	command := fmt.Sprintf("set>server=%s:8899;", localIP)
	_, err = udpConn.Write([]byte(command))
	if err != nil {
		fmt.Printf("Failed to send UDP command: %v\n", err)
		os.Exit(1)
	}
	udpConn.Close()

	fmt.Printf("Sent command to datalogger: %s\n", command)
	fmt.Println("Waiting for datalogger to connect...")

	// Step 3: Accept connection from datalogger
	tcpConn, err := listener.Accept()
	if err != nil {
		fmt.Printf("Failed to accept connection: %v\n", err)
		os.Exit(1)
	}
	defer tcpConn.Close()

	fmt.Printf("✓ Datalogger connected from: %s\n", tcpConn.RemoteAddr())
	fmt.Println("\nListening for data...")
	fmt.Println("Press Ctrl+C to exit\n")

	// Step 4: Just listen and print any data received
	buffer := make([]byte, 4096)
	for {
		// Set read timeout
		tcpConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, err := tcpConn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Println("No data received for 30 seconds...")
				continue
			}
			fmt.Printf("Read error: %v\n", err)
			break
		}

		if n > 0 {
			fmt.Printf("Received %d bytes:\n", n)
			fmt.Printf("Hex: %x\n", buffer[:n])
			fmt.Printf("ASCII: %s\n", tryASCII(buffer[:n]))
			fmt.Println("---")
		}
	}
}

func tryASCII(data []byte) string {
	result := ""
	for _, b := range data {
		if b >= 32 && b <= 126 {
			result += string(b)
		} else {
			result += "."
		}
	}
	return result
}
