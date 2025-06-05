package main

import (
	"fmt"
	"net"
	"strings"
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

	// Set buffer sizes
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
	buffer := make([]byte, 4096) // Larger buffer for potentially long responses
	n, err := dlc.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(buffer[:n]), nil
}

// DiscoverCommands tries various command formats to find valid ones
func (dlc *DataLoggerConnection) DiscoverCommands() {
	fmt.Println("=== Command Discovery ===")
	fmt.Println("Trying various command formats...")

	// Common command variations for PV/Solar systems
	commands := []struct {
		category string
		cmds     []string
	}{
		{
			"Basic Info Commands",
			[]string{
				"INFO", "STATUS", "GET STATUS", "DEVICE INFO",
				"VERSION", "ID", "SERIAL", "MODEL",
				"?", "HELP", "H", "LIST",
			},
		},
		{
			"PV Power Commands",
			[]string{
				"READ", "READ ALL", "READ_ALL", "READALL",
				"GET DATA", "GET_DATA", "GETDATA",
				"PV", "PV POWER", "PV_POWER", "PVPOWER",
				"POWER", "P", "PWR", "W",
				"READ PV", "READ_PV", "GET PV", "GET_PV",
				"SOLAR", "SOLAR POWER", "GENERATION",
			},
		},
		{
			"Modbus-style Commands",
			[]string{
				"01 03 00 00 00 01", // Modbus read holding registers
				"01 04 00 00 00 01", // Modbus read input registers
				":010300000001FA",   // Modbus ASCII
				"$01M",              // Some proprietary formats
			},
		},
		{
			"JSON Commands",
			[]string{
				`{"command":"read"}`,
				`{"cmd":"get_data"}`,
				`{"action":"read_pv"}`,
				`{"get":"power"}`,
			},
		},
		{
			"XML Commands",
			[]string{
				"<request><command>read</command></request>",
				"<get>power</get>",
				"<?xml version='1.0'?><cmd>status</cmd>",
			},
		},
	}

	// Try each command
	for _, group := range commands {
		fmt.Printf("\n--- %s ---\n", group.category)
		for _, cmd := range group.cmds {
			fmt.Printf("Trying: %-30s -> ", cmd)

			response, err := dlc.SendCommand(cmd)
			if err != nil {
				// Check if it's a timeout (might mean no response expected)
				if strings.Contains(err.Error(), "timeout") {
					fmt.Println("No response (timeout)")
				} else {
					fmt.Printf("Error: %v\n", err)
				}
			} else {
				// Got a response!
				if len(response) > 50 {
					fmt.Printf("Response: %.50s... (length: %d)\n", response, len(response))
				} else {
					fmt.Printf("Response: %s\n", response)
				}

				// Try to identify if this looks like valid data
				if looksLikeValidData(response) {
					fmt.Printf("    ^^^ This looks like valid data! ^^^\n")
				}
			}

			// Small delay between commands
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// looksLikeValidData tries to identify if response contains valid data
func looksLikeValidData(response string) bool {
	// Check for common patterns in valid responses
	checks := []func(string) bool{
		// Contains numbers (likely measurements)
		func(s string) bool {
			for _, r := range s {
				if r >= '0' && r <= '9' {
					return true
				}
			}
			return false
		},
		// JSON-like
		func(s string) bool {
			return strings.Contains(s, "{") && strings.Contains(s, "}")
		},
		// CSV-like
		func(s string) bool {
			return strings.Contains(s, ",") || strings.Contains(s, ";")
		},
		// Key-value pairs
		func(s string) bool {
			return strings.Contains(s, "=") || strings.Contains(s, ":")
		},
		// Not an error message
		func(s string) bool {
			lower := strings.ToLower(s)
			return !strings.Contains(lower, "error") &&
				!strings.Contains(lower, "invalid") &&
				!strings.Contains(lower, "unknown")
		},
	}

	validChecks := 0
	for _, check := range checks {
		if check(response) {
			validChecks++
		}
	}

	return validChecks >= 2
}

// TryBinaryProtocol sends binary data patterns
func (dlc *DataLoggerConnection) TryBinaryProtocol() {
	fmt.Println("\n=== Trying Binary Protocols ===")

	// Common binary protocols for solar/PV systems
	binaryCommands := []struct {
		name string
		data []byte
	}{
		{"Modbus RTU Read", []byte{0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x84, 0x0A}},
		{"Simple Binary", []byte{0x01, 0x00}},
		{"STX/ETX Protocol", []byte{0x02, 0x52, 0x03}}, // STX + 'R' + ETX
		{"Binary with CRC", []byte{0xAA, 0x55, 0x01, 0x00, 0xFF}},
	}

	for _, cmd := range binaryCommands {
		fmt.Printf("Trying %s: % X -> ", cmd.name, cmd.data)

		_, err := dlc.Write(cmd.data)
		if err != nil {
			fmt.Printf("Write error: %v\n", err)
			continue
		}

		buffer := make([]byte, 1024)
		n, err := dlc.Read(buffer)
		if err != nil {
			fmt.Println("No response")
		} else {
			fmt.Printf("Response: % X (ASCII: %s)\n", buffer[:n], tryASCII(buffer[:n]))
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// tryASCII attempts to show ASCII representation of binary data
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
	fmt.Println()

	// Try to discover commands
	logger.DiscoverCommands()

	// Also try binary protocols
	logger.TryBinaryProtocol()

	// If you want to test a specific command
	fmt.Println("\n=== Manual Command Test ===")
	fmt.Println("Testing specific command for PV power...")

	// Try some more specific PV commands
	testCommands := []string{
		"GET:POWER",
		"READ:PV:POWER",
		"QUERY:PV",
		"*IDN?",      // SCPI standard
		":MEAS:POW?", // SCPI measurement
		"QPI",        // Some inverters use this
		"QPGS0",      // Status query
	}

	for _, cmd := range testCommands {
		fmt.Printf("\nTrying: %s\n", cmd)
		response, err := logger.SendCommand(cmd)
		if err == nil {
			fmt.Printf("Response: %s\n", response)
		}
	}
}
