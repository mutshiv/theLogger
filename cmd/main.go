package main

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DataLoggerConnection with enhanced error handling and diagnostics
type DataLoggerConnection struct {
	protocol     string
	address      string
	tcpConn      net.Conn
	udpConn      *net.UDPConn
	udpAddr      *net.UDPAddr
	readTimeout  time.Duration
	writeTimeout time.Duration
	mu           sync.Mutex
	debug        bool
}

// NewDataLoggerConnection creates a new connection handler
func NewDataLoggerConnection(protocol, ip, port string) *DataLoggerConnection {
	return &DataLoggerConnection{
		protocol:     protocol,
		address:      fmt.Sprintf("%s:%s", ip, port),
		readTimeout:  5 * time.Second,
		writeTimeout: 5 * time.Second,
		debug:        true, // Enable debug logging
	}
}

// NetworkDiagnostics performs comprehensive network checks
func (dlc *DataLoggerConnection) NetworkDiagnostics() {
	fmt.Println("=== Network Diagnostics ===")

	// Parse IP and port
	host, port, _ := net.SplitHostPort(dlc.address)

	// 1. Check local network interfaces
	fmt.Println("\n1. Local Network Interfaces:")
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					fmt.Printf("   %s: %s\n", iface.Name, ipnet.IP.String())
				}
			}
		}
	}

	// 2. ARP table check (to see if device is in ARP cache)
	fmt.Println("\n2. ARP Table Check:")
	dlc.checkARP(host)

	// 3. Port scan on common ports
	fmt.Println("\n3. Port Scan:")
	commonPorts := []string{"80", "443", "8080", "8888", "9999", "23", "22", port}
	for _, p := range commonPorts {
		if dlc.checkPort(host, p) {
			fmt.Printf("   Port %s: OPEN\n", p)
		} else {
			fmt.Printf("   Port %s: CLOSED/FILTERED\n", p)
		}
	}

	// 4. Check firewall status
	fmt.Println("\n4. Local Firewall Status:")
	dlc.checkFirewall()

	// 5. Route check
	fmt.Println("\n5. Routing Table:")
	dlc.checkRoutes()
}

// checkARP checks if the device appears in ARP table
func (dlc *DataLoggerConnection) checkARP(ip string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin", "linux":
		cmd = exec.Command("arp", "-n")
	case "windows":
		cmd = exec.Command("arp", "-a")
	default:
		fmt.Println("   ARP check not supported on this OS")
		return
	}

	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("   Failed to check ARP: %v\n", err)
		return
	}

	if strings.Contains(string(output), ip) {
		fmt.Printf("   ✓ Device %s found in ARP table\n", ip)
	} else {
		fmt.Printf("   ✗ Device %s NOT in ARP table\n", ip)
	}
}

// checkPort tests if a specific port is open
func (dlc *DataLoggerConnection) checkPort(host, port string) bool {
	timeout := 2 * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// checkFirewall checks local firewall status
func (dlc *DataLoggerConnection) checkFirewall() {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("sudo", "pfctl", "-s", "info")
		output, _ := cmd.Output()
		fmt.Printf("   %s\n", string(output))
	case "linux":
		cmd := exec.Command("sudo", "iptables", "-L", "-n")
		output, _ := cmd.Output()
		if len(output) > 0 {
			fmt.Println("   Firewall rules active")
		}
	case "windows":
		cmd := exec.Command("netsh", "advfirewall", "show", "allprofiles")
		output, _ := cmd.Output()
		fmt.Printf("   %s\n", string(output))
	}
}

// checkRoutes displays routing table
func (dlc *DataLoggerConnection) checkRoutes() {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("netstat", "-rn")
	case "linux":
		cmd = exec.Command("ip", "route")
	case "windows":
		cmd = exec.Command("route", "print")
	}

	output, _ := cmd.Output()
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i < 5 || strings.Contains(line, "192.168") {
			fmt.Printf("   %s\n", line)
		}
	}
}

// Connect with enhanced error reporting
func (dlc *DataLoggerConnection) Connect() error {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	if dlc.debug {
		fmt.Printf("Attempting %s connection to %s...\n", dlc.protocol, dlc.address)
	}

	switch dlc.protocol {
	case "tcp":
		return dlc.connectTCPEnhanced()
	case "udp":
		return dlc.connectUDPEnhanced()
	default:
		return fmt.Errorf("unsupported protocol: %s", dlc.protocol)
	}
}

// connectTCPEnhanced establishes TCP connection with detailed error info
func (dlc *DataLoggerConnection) connectTCPEnhanced() error {
	// Close existing connection if any
	if dlc.tcpConn != nil {
		dlc.tcpConn.Close()
	}

	// Try different connection methods
	host, port, _ := net.SplitHostPort(dlc.address)

	// Method 1: Direct dial with timeout
	dialer := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.Dial("tcp", dlc.address)
	if err != nil {
		// Check specific error types
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Timeout() {
				return fmt.Errorf("connection timeout - device may be using different port or blocking connections")
			}
			if strings.Contains(err.Error(), "connection refused") {
				return fmt.Errorf("connection refused - port %s closed or service not running", port)
			}
			if strings.Contains(err.Error(), "no route to host") {
				return fmt.Errorf("no route to host - check if %s is correct IP and you're on same network", host)
			}
		}
		return fmt.Errorf("TCP connection failed: %w", err)
	}

	// Set socket options for better reliability
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true) // Disable Nagle's algorithm
	}

	dlc.tcpConn = conn

	if dlc.debug {
		fmt.Printf("✓ TCP connection established to %s\n", dlc.address)
	}

	return nil
}

// connectUDPEnhanced establishes UDP connection
func (dlc *DataLoggerConnection) connectUDPEnhanced() error {
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

	if dlc.debug {
		fmt.Printf("✓ UDP connection established to %s\n", dlc.address)
	}

	return nil
}

// AlternativeConnect tries different connection strategies
func (dlc *DataLoggerConnection) AlternativeConnect() error {
	host, port, _ := net.SplitHostPort(dlc.address)

	fmt.Println("Trying alternative connection methods...")

	// 1. Try without timeout (some devices are slow)
	fmt.Printf("1. Attempting connection without timeout...")
	conn, err := net.Dial(dlc.protocol, dlc.address)
	if err == nil {
		dlc.tcpConn = conn
		fmt.Println(" SUCCESS")
		return nil
	}
	fmt.Printf(" FAILED: %v\n", err)

	// 2. Try broadcast discovery (UDP only)
	if dlc.protocol == "udp" {
		fmt.Printf("2. Attempting UDP broadcast discovery...")
		dlc.udpBroadcastDiscovery(port)
	}

	// 3. Try common datalogger ports
	fmt.Println("3. Trying common datalogger ports...")
	commonPorts := []string{"502", "2000", "2101", "4001", "5000", "9999", "10001"}
	for _, p := range commonPorts {
		addr := net.JoinHostPort(host, p)
		fmt.Printf("   Trying %s...", addr)

		conn, err := net.DialTimeout(dlc.protocol, addr, 3*time.Second)
		if err == nil {
			dlc.tcpConn = conn
			dlc.address = addr
			fmt.Println(" SUCCESS")
			return nil
		}
		fmt.Println(" FAILED")
	}

	return fmt.Errorf("all connection attempts failed")
}

// udpBroadcastDiscovery attempts to discover device via UDP broadcast
func (dlc *DataLoggerConnection) udpBroadcastDiscovery(port string) {
	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("255.255.255.255:%s", port))
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Printf(" FAILED: %v\n", err)
		return
	}
	defer conn.Close()

	// Send discovery packet
	conn.Write([]byte("DISCOVER"))

	// Wait for response
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, remoteAddr, err := conn.ReadFromUDP(buffer)
	if err == nil {
		fmt.Printf(" FOUND device at %s: %s\n", remoteAddr, string(buffer[:n]))
	} else {
		fmt.Printf(" No response\n")
	}
}

// Write with debug logging
func (dlc *DataLoggerConnection) Write(data []byte) (int, error) {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	if dlc.debug {
		fmt.Printf(">> Sending: %s", string(data))
	}

	switch dlc.protocol {
	case "tcp":
		if dlc.tcpConn == nil {
			return 0, fmt.Errorf("TCP connection not established")
		}
		dlc.tcpConn.SetWriteDeadline(time.Now().Add(dlc.writeTimeout))
		return dlc.tcpConn.Write(data)

	case "udp":
		if dlc.udpConn == nil {
			return 0, fmt.Errorf("UDP connection not established")
		}
		dlc.udpConn.SetWriteDeadline(time.Now().Add(dlc.writeTimeout))
		return dlc.udpConn.Write(data)

	default:
		return 0, fmt.Errorf("unsupported protocol")
	}
}

// Read with debug logging
func (dlc *DataLoggerConnection) Read(buffer []byte) (int, error) {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	var n int
	var err error

	switch dlc.protocol {
	case "tcp":
		if dlc.tcpConn == nil {
			return 0, fmt.Errorf("TCP connection not established")
		}
		dlc.tcpConn.SetReadDeadline(time.Now().Add(dlc.readTimeout))
		n, err = dlc.tcpConn.Read(buffer)

	case "udp":
		if dlc.udpConn == nil {
			return 0, fmt.Errorf("UDP connection not established")
		}
		dlc.udpConn.SetReadDeadline(time.Now().Add(dlc.readTimeout))
		n, err = dlc.udpConn.Read(buffer)

	default:
		return 0, fmt.Errorf("unsupported protocol")
	}

	if err == nil && dlc.debug {
		fmt.Printf("<< Received: %s\n", string(buffer[:n]))
	}

	return n, err
}

// Example usage with troubleshooting
func main() {
	// Common datalogger configurations
	configs := []struct {
		name     string
		protocol string
		ip       string
		port     string
	}{
		{"TCP on 8080", "tcp", "192.168.88.93", "8080"},
		{"TCP on 502 (Modbus)", "tcp", "192.168.88.93", "502"},
		{"TCP on 23 (Telnet)", "tcp", "192.168.88.93", "23"},
		{"UDP on 9999", "udp", "192.168.88.93", "9999"},
	}

	// Run diagnostics first
	fmt.Println("Running network diagnostics...")
	logger := NewDataLoggerConnection("tcp", "192.168.4.1", "8080")
	logger.NetworkDiagnostics()

	// Try different configurations
	fmt.Println("\n\nTrying different connection configurations...")
	for _, config := range configs {
		fmt.Printf("\nTrying %s...\n", config.name)
		logger := NewDataLoggerConnection(config.protocol, config.ip, config.port)

		err := logger.Connect()
		if err == nil {
			fmt.Printf("✓ SUCCESS: Connected using %s\n", config.name)

			// Test the connection
			response, err := logger.SendCommand("INFO")
			if err == nil {
				fmt.Printf("Device responded: %s\n", response)
			}

			logger.Close()
			break
		} else {
			fmt.Printf("✗ FAILED: %v\n", err)
		}
	}
}

// SendCommand helper function
func (dlc *DataLoggerConnection) SendCommand(command string) (string, error) {
	_, err := dlc.Write([]byte(command + "\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send command: %w", err)
	}

	buffer := make([]byte, 1024)
	n, err := dlc.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(buffer[:n]), nil
}

// Close connection
func (dlc *DataLoggerConnection) Close() error {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	var err error
	switch dlc.protocol {
	case "tcp":
		if dlc.tcpConn != nil {
			err = dlc.tcpConn.Close()
			dlc.tcpConn = nil
		}
	case "udp":
		if dlc.udpConn != nil {
			err = dlc.udpConn.Close()
			dlc.udpConn = nil
		}
	}

	return err
}
