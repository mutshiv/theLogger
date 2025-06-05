package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// DataLoggerConnection handles UDP connection to the datalogger
type DataLoggerConnection struct {
	protocol     string
	address      string
	udpConn      *net.UDPConn
	udpAddr      *net.UDPAddr
	readTimeout  time.Duration
	writeTimeout time.Duration
	mu           sync.Mutex
}

// NewDataLoggerConnection creates a new connection handler
func NewDataLoggerConnection(protocol, ip, port string) *DataLoggerConnection {
	return &DataLoggerConnection{
		protocol:     protocol,
		address:      fmt.Sprintf("%s:%s", ip, port),
		readTimeout:  5 * time.Second,
		writeTimeout: 5 * time.Second,
	}
}

// Connect establishes UDP connection
func (dlc *DataLoggerConnection) Connect() error {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	if dlc.protocol != "udp" {
		return fmt.Errorf("unsupported protocol: %s", dlc.protocol)
	}

	// Resolve UDP address
	udpAddr, err := net.ResolveUDPAddr("udp", dlc.address)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	// Create UDP connection
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("UDP connection failed: %w", err)
	}

	// Set buffer sizes for better performance
	conn.SetReadBuffer(65536)
	conn.SetWriteBuffer(65536)

	dlc.udpConn = conn
	dlc.udpAddr = udpAddr

	return nil
}

// Write sends data to the datalogger
func (dlc *DataLoggerConnection) Write(data []byte) (int, error) {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	if dlc.udpConn == nil {
		return 0, fmt.Errorf("UDP connection not established")
	}

	dlc.udpConn.SetWriteDeadline(time.Now().Add(dlc.writeTimeout))
	return dlc.udpConn.Write(data)
}

// Read reads data from the datalogger
func (dlc *DataLoggerConnection) Read(buffer []byte) (int, error) {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	if dlc.udpConn == nil {
		return 0, fmt.Errorf("UDP connection not established")
	}

	dlc.udpConn.SetReadDeadline(time.Now().Add(dlc.readTimeout))
	return dlc.udpConn.Read(buffer)
}

// SendCommand sends a command and waits for response
func (dlc *DataLoggerConnection) SendCommand(command string) (string, error) {
	// Send command
	_, err := dlc.Write([]byte(command))
	if err != nil {
		return "", fmt.Errorf("failed to send command: %w", err)
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := dlc.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(buffer[:n]), nil
}

// Close closes the connection
func (dlc *DataLoggerConnection) Close() error {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	if dlc.udpConn != nil {
		err := dlc.udpConn.Close()
		dlc.udpConn = nil
		return err
	}

	return nil
}

// SetTimeouts configures read and write timeouts
func (dlc *DataLoggerConnection) SetTimeouts(read, write time.Duration) {
	dlc.readTimeout = read
	dlc.writeTimeout = write
}

// IsConnected checks if connection is active
func (dlc *DataLoggerConnection) IsConnected() bool {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	return dlc.udpConn != nil
}

// Example usage
func main() {
	// Create UDP connection to datalogger
	logger := NewDataLoggerConnection("udp", "192.168.4.1", "9999")

	// Connect
	if err := logger.Connect(); err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer logger.Close()

	fmt.Println("Connected to datalogger on UDP port 9999")

	// Send command and read response
	response, err := logger.SendCommand("READ_DATA")
	if err != nil {
		fmt.Printf("Command failed: %v\n", err)
		return
	}

	fmt.Printf("Response: %s\n", response)

	// Example of continuous reading
	go func() {
		for {
			buffer := make([]byte, 1024)
			n, err := logger.Read(buffer)
			if err != nil {
				fmt.Printf("Read error: %v\n", err)
				continue
			}
			fmt.Printf("Received: %s\n", string(buffer[:n]))
		}
	}()

	// Keep main thread alive
	select {}
}
