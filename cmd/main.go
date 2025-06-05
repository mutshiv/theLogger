package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// DataLoggerConnection for SmartESS WiFi datalogger
type DataLoggerConnection struct {
	dataloggerIP string
	localIP      string
	udpConn      *net.UDPConn
	tcpListener  net.Listener
	tcpConn      net.Conn
	mu           sync.Mutex
}

// NewDataLoggerConnection creates a new connection handler
func NewDataLoggerConnection(dataloggerIP string) (*DataLoggerConnection, error) {
	// Get local IP address on the same network as the datalogger
	localIP, err := getLocalIP(dataloggerIP)
	if err != nil {
		return nil, fmt.Errorf("failed to get local IP: %w", err)
	}

	return &DataLoggerConnection{
		dataloggerIP: dataloggerIP,
		localIP:      localIP,
	}, nil
}

// getLocalIP returns the local IP address on the same subnet as the datalogger
func getLocalIP(dataloggerIP string) (string, error) {
	// Parse datalogger IP to get the network prefix
	parts := strings.Split(dataloggerIP, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid datalogger IP format")
	}
	networkPrefix := strings.Join(parts[:3], ".")

	fmt.Printf("Looking for IP in network: %s.x\n", networkPrefix)

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		// Skip down interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ip := ipnet.IP.String()

				// Check if this IP is in the same subnet as the datalogger
				if strings.HasPrefix(ip, networkPrefix+".") {
					fmt.Printf("✓ Found matching IP: %s (interface: %s)\n", ip, iface.Name)
					return ip, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no IP address found in %s.x network", networkPrefix)
}

// Connect establishes connection with the datalogger
func (dlc *DataLoggerConnection) Connect() error {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	fmt.Printf("Using local IP: %s\n", dlc.localIP)
	fmt.Printf("Datalogger IP: %s\n", dlc.dataloggerIP)

	// Step 1: Create TCP listener on port 8899
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:8899", dlc.localIP))
	if err != nil {
		return fmt.Errorf("failed to create TCP listener on %s:8899: %w", dlc.localIP, err)
	}
	fmt.Printf("TCP listener created on %s:8899\n", dlc.localIP)
	dlc.tcpListener = listener

	// Step 2: Start goroutine to accept connection
	go dlc.acceptConnection()

	// Step 3: Send UDP command to datalogger
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:58899", dlc.dataloggerIP))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("failed to create UDP connection: %w", err)
	}
	dlc.udpConn = conn

	// Send command to make datalogger connect to us
	command := fmt.Sprintf("set>server=%s:8899;", dlc.localIP)
	_, err = conn.Write([]byte(command))
	if err != nil {
		return fmt.Errorf("failed to send UDP command: %w", err)
	}

	fmt.Printf("Sent UDP command: %s\n", command)

	// Wait for response
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Printf("Warning: No UDP response (timeout). This might be normal.\n")
	} else {
		response := string(buffer[:n])
		fmt.Printf("UDP Response: %s\n", response)
	}

	// Wait for TCP connection
	fmt.Println("Waiting for datalogger to connect back...")
	time.Sleep(3 * time.Second)

	if dlc.tcpConn == nil {
		return fmt.Errorf("datalogger didn't connect back on TCP")
	}

	return nil
}

// acceptConnection accepts incoming TCP connection from datalogger
func (dlc *DataLoggerConnection) acceptConnection() {
	fmt.Println("Waiting for incoming TCP connection...")
	conn, err := dlc.tcpListener.Accept()
	if err != nil {
		fmt.Printf("Failed to accept connection: %v\n", err)
		return
	}

	dlc.mu.Lock()
	dlc.tcpConn = conn
	dlc.mu.Unlock()

	fmt.Printf("✓ Datalogger connected from: %s\n", conn.RemoteAddr())
}

// QueryAllData sends the magic command to get all inverter data
func (dlc *DataLoggerConnection) QueryAllData() (map[string]interface{}, error) {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	if dlc.tcpConn == nil {
		return nil, fmt.Errorf("no TCP connection established")
	}

	// Magic command discovered by network sniffing
	// HEX: aaaa00010003001100
	magicCmd, _ := hex.DecodeString("aaaa00010003001100")

	_, err := dlc.tcpConn.Write(magicCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to send command: %w", err)
	}

	// Read response
	buffer := make([]byte, 4096)
	dlc.tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := dlc.tcpConn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	return dlc.parseAllDataResponse(buffer[:n])
}

// parseAllDataResponse parses the all-in-one data packet
func (dlc *DataLoggerConnection) parseAllDataResponse(data []byte) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	if len(data) < 100 {
		return nil, fmt.Errorf("response too short: %d bytes", len(data))
	}

	// Skip header bytes
	offset := 9

	// Parse various fields (positions may vary by model)
	// PV Power (Watts) - typically at offset 33-34
	if len(data) > offset+34 {
		pvPower := binary.BigEndian.Uint16(data[offset+33 : offset+35])
		result["pv_power_w"] = pvPower
	}

	// Battery Voltage - typically at offset 37-38
	if len(data) > offset+38 {
		batteryVoltage := float32(binary.BigEndian.Uint16(data[offset+37:offset+39])) / 10.0
		result["battery_voltage"] = batteryVoltage
	}

	// Load Power - typically at offset 41-42
	if len(data) > offset+42 {
		loadPower := binary.BigEndian.Uint16(data[offset+41 : offset+43])
		result["load_power_w"] = loadPower
	}

	// Grid Power - typically at offset 45-46
	if len(data) > offset+46 {
		gridPower := int16(binary.BigEndian.Uint16(data[offset+45 : offset+47]))
		result["grid_power_w"] = gridPower
	}

	// Daily PV Generation - typically at offset 59-60
	if len(data) > offset+60 {
		dailyGeneration := float32(binary.BigEndian.Uint16(data[offset+59:offset+61])) / 10.0
		result["daily_generation_kwh"] = dailyGeneration
	}

	// Debug: show hex dump of data
	fmt.Printf("Raw data (first 100 bytes): %x\n", data[:min(100, len(data))])

	return result, nil
}

// QueryModbus sends standard Modbus TCP commands
func (dlc *DataLoggerConnection) QueryModbus(slaveID byte, functionCode byte, address uint16, quantity uint16) ([]byte, error) {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	if dlc.tcpConn == nil {
		return nil, fmt.Errorf("no TCP connection established")
	}

	// Build Modbus TCP frame
	transactionID := uint16(1)
	protocolID := uint16(0)
	length := uint16(6)

	frame := new(bytes.Buffer)
	binary.Write(frame, binary.BigEndian, transactionID)
	binary.Write(frame, binary.BigEndian, protocolID)
	binary.Write(frame, binary.BigEndian, length)
	frame.WriteByte(slaveID)
	frame.WriteByte(functionCode)
	binary.Write(frame, binary.BigEndian, address)
	binary.Write(frame, binary.BigEndian, quantity)

	// Send command
	_, err := dlc.tcpConn.Write(frame.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to send Modbus command: %w", err)
	}

	// Read response
	buffer := make([]byte, 256)
	dlc.tcpConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := dlc.tcpConn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read Modbus response: %w", err)
	}

	return buffer[:n], nil
}

// GetPVPower tries different methods to get PV power
func (dlc *DataLoggerConnection) GetPVPower() (float64, error) {
	// Method 1: Try the all-data command
	data, err := dlc.QueryAllData()
	if err == nil {
		if pvPower, ok := data["pv_power_w"].(uint16); ok {
			return float64(pvPower), nil
		}
	}

	// Method 2: Try Modbus registers (common PV power registers)
	// Register 0x0102 is common for PV power in many inverters
	response, err := dlc.QueryModbus(1, 3, 0x0102, 1)
	if err == nil && len(response) >= 9 {
		// Skip Modbus TCP header (7 bytes) + function code (1 byte) + byte count (1 byte)
		if len(response) >= 11 {
			pvPower := binary.BigEndian.Uint16(response[9:11])
			return float64(pvPower), nil
		}
	}

	return 0, fmt.Errorf("failed to get PV power")
}

// Close closes all connections
func (dlc *DataLoggerConnection) Close() error {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	if dlc.udpConn != nil {
		dlc.udpConn.Close()
	}

	if dlc.tcpConn != nil {
		dlc.tcpConn.Close()
	}

	if dlc.tcpListener != nil {
		dlc.tcpListener.Close()
	}

	return nil
}

// tryAlternativeCommands tests different protocol variations
func (dlc *DataLoggerConnection) tryAlternativeCommands() {
	fmt.Println("\nTrying alternative commands...")

	// Try different hex commands that might work
	commands := map[string]string{
		"Alt Magic 1":  "aaaa000100030011",
		"Alt Magic 2":  "0103000000010000",
		"Status Query": "010300000001840a",
		"Read All":     "0104000000010000",
	}

	for name, hexCmd := range commands {
		cmd, _ := hex.DecodeString(hexCmd)
		fmt.Printf("\nTrying %s: %x\n", name, cmd)

		dlc.mu.Lock()
		dlc.tcpConn.Write(cmd)

		buffer := make([]byte, 1024)
		dlc.tcpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := dlc.tcpConn.Read(buffer)
		dlc.mu.Unlock()

		if err == nil && n > 0 {
			fmt.Printf("Response (%d bytes): %x\n", n, buffer[:n])
			if n > 20 {
				fmt.Println("This looks like valid data!")
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] <datalogger-ip>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nExample:\n")
	fmt.Fprintf(os.Stderr, "  %s 192.168.88.88\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -discover\n", os.Args[0])
}

// discoverDatalogger attempts to find the datalogger on the network
func discoverDatalogger() (string, error) {
	fmt.Println("Discovering datalogger on the network...")

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	// Look for IPs in common ranges
	commonRanges := []string{"192.168.88", "192.168.4", "192.168.1", "10.10.10"}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ip := ipnet.IP.String()

				// Check if we're in a common range
				for _, prefix := range commonRanges {
					if strings.HasPrefix(ip, prefix+".") {
						// Try common gateway IPs
						candidates := []string{
							prefix + ".1",
							prefix + ".88",
							prefix + ".254",
						}

						fmt.Printf("Found local IP %s, checking potential dataloggers...\n", ip)

						for _, candidate := range candidates {
							fmt.Printf("Trying %s... ", candidate)

							// Try to connect to UDP port 58899
							udpAddr, _ := net.ResolveUDPAddr("udp", candidate+":58899")
							conn, err := net.DialUDP("udp", nil, udpAddr)
							if err != nil {
								fmt.Println("Failed")
								continue
							}

							// Send a simple query
							conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
							_, err = conn.Write([]byte("query"))
							if err != nil {
								conn.Close()
								fmt.Println("Failed")
								continue
							}

							// Wait for any response
							buffer := make([]byte, 1024)
							conn.SetReadDeadline(time.Now().Add(2 * time.Second))
							_, _, err = conn.ReadFromUDP(buffer)
							conn.Close()

							if err == nil {
								fmt.Println("✓ Found!")
								return candidate, nil
							}
							fmt.Println("No response")
						}
					}
				}
			}
		}
	}

	return "", fmt.Errorf("no datalogger found on the network")
}

func main() {
	// Define command-line flags
	var discover bool
	flag.BoolVar(&discover, "discover", false, "Attempt to discover datalogger IP automatically")
	flag.Usage = printUsage
	flag.Parse()

	var dataloggerIP string

	if discover {
		// Try to discover the datalogger
		ip, err := discoverDatalogger()
		if err != nil {
			fmt.Printf("Failed to discover datalogger: %v\n", err)
			fmt.Println("\nPlease specify the datalogger IP manually")
			os.Exit(1)
		}
		dataloggerIP = ip
		fmt.Printf("\nDiscovered datalogger at: %s\n", dataloggerIP)
	} else {
		// Check if IP address was provided
		if flag.NArg() < 1 {
			printUsage()
			os.Exit(1)
		}
		dataloggerIP = flag.Arg(0)

		// Validate IP format
		if net.ParseIP(dataloggerIP) == nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid IP address format: %s\n", dataloggerIP)
			os.Exit(1)
		}
	}

	fmt.Println("=== SmartESS Datalogger Connection ===")
	fmt.Printf("Datalogger IP: %s\n", dataloggerIP)
	fmt.Println("=====================================\n")

	// Create connection to datalogger
	dlc, err := NewDataLoggerConnection(dataloggerIP)
	if err != nil {
		fmt.Printf("Failed to create connection: %v\n", err)
		fmt.Println("\nMake sure you're connected to the datalogger's WiFi network")
		os.Exit(1)
	}
	defer dlc.Close()

	fmt.Println("Connecting to datalogger...")

	// Connect
	if err := dlc.Connect(); err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		fmt.Println("\nTroubleshooting:")
		fmt.Println("1. Make sure no firewall is blocking port 8899")
		fmt.Println("2. Ensure the SmartESS app is not connected")
		fmt.Println("3. Try power cycling the datalogger")
		fmt.Println("4. Verify the IP address is correct")
		os.Exit(1)
	}

	fmt.Println("Connected! Querying data...")

	// Get all data
	data, err := dlc.QueryAllData()
	if err != nil {
		fmt.Printf("Failed to query data: %v\n", err)
		fmt.Println("\nThe datalogger connected but may use a different protocol.")
		fmt.Println("Trying alternative methods...")

		// Try some alternative commands
		dlc.tryAlternativeCommands()
	} else {
		fmt.Println("\n=== Inverter Data ===")
		for key, value := range data {
			fmt.Printf("%s: %v\n", key, value)
		}
	}

	// Get PV power specifically
	pvPower, err := dlc.GetPVPower()
	if err != nil {
		fmt.Printf("\nFailed to get PV power: %v\n", err)
	} else {
		fmt.Printf("\nCurrent PV Power: %.1f W\n", pvPower)
	}
}
