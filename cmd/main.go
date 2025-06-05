package main

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"time"
)

type DataLoggerConnection struct {
	protocol     string
	address      string
	tcpConn      net.Conn
	udpConn      *net.UDPConn
	udpAddr      *net.UDPAddr
	readTimeout  time.Duration
	writeTimeout time.Duration
	mu           sync.Mutex
}

func NewDataLoggerConnection(protocol, ip, port string) *DataLoggerConnection {
	return &DataLoggerConnection{
		protocol:     protocol,
		address:      fmt.Sprintf("%s:%s", ip, port),
		readTimeout:  5 * time.Second,
		writeTimeout: 5 * time.Second,
	}
}

func (dlc *DataLoggerConnection) Connect() error {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	switch dlc.protocol {
	case "tcp":
		return dlc.connectTCP()
	case "udp":
		return dlc.connectUDP()
	default:
		return fmt.Errorf("unsupported protocol: %s", dlc.protocol)
	}
}

func (dlc *DataLoggerConnection) connectTCP() error {
	// Close existing connection if any
	if dlc.tcpConn != nil {
		dlc.tcpConn.Close()
	}

	// Dial with timeout
	dialer := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.Dial("tcp", dlc.address)
	if err != nil {
		return fmt.Errorf("TCP connection failed: %w", err)
	}

	dlc.tcpConn = conn
	return nil
}

func (dlc *DataLoggerConnection) connectUDP() error {
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

	dlc.udpConn = conn
	dlc.udpAddr = udpAddr
	return nil
}

func (dlc *DataLoggerConnection) IsConnected() bool {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	switch dlc.protocol {
	case "tcp":
		if dlc.tcpConn == nil {
			return false
		}
		// Test connection by setting a deadline
		dlc.tcpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 1)
		_, err := dlc.tcpConn.Read(buf)
		dlc.tcpConn.SetReadDeadline(time.Time{}) // Reset deadline

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return true // Timeout means connection is still alive
			}
			return false
		}
		return true

	case "udp":
		return dlc.udpConn != nil
	default:
		return false
	}
}

func (dlc *DataLoggerConnection) Reconnect(maxRetries int) error {
	for i := 0; i < maxRetries; i++ {
		err := dlc.Connect()
		if err == nil {
			fmt.Printf("Reconnected successfully on attempt %d\n", i+1)
			return nil
		}

		waitTime := time.Duration(1<<uint(i)) * time.Second // Exponential backoff
		fmt.Printf("Connection attempt %d failed: %v. Retrying in %v...\n", i+1, err, waitTime)
		time.Sleep(waitTime)
	}

	return fmt.Errorf("failed to reconnect after %d attempts", maxRetries)
}

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

func (dlc *DataLoggerConnection) SetTimeouts(read, write time.Duration) {
	dlc.readTimeout = read
	dlc.writeTimeout = write
}

func (dlc *DataLoggerConnection) Write(data []byte) (int, error) {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

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

func (dlc *DataLoggerConnection) Read(buffer []byte) (int, error) {
	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	switch dlc.protocol {
	case "tcp":
		if dlc.tcpConn == nil {
			return 0, fmt.Errorf("TCP connection not established")
		}
		dlc.tcpConn.SetReadDeadline(time.Now().Add(dlc.readTimeout))
		return dlc.tcpConn.Read(buffer)

	case "udp":
		if dlc.udpConn == nil {
			return 0, fmt.Errorf("UDP connection not established")
		}
		dlc.udpConn.SetReadDeadline(time.Now().Add(dlc.readTimeout))
		return dlc.udpConn.Read(buffer)

	default:
		return 0, fmt.Errorf("unsupported protocol")
	}
}

func (dlc *DataLoggerConnection) ReadLine() (string, error) {
	if dlc.protocol != "tcp" {
		return "", fmt.Errorf("ReadLine only supported for TCP")
	}

	dlc.mu.Lock()
	defer dlc.mu.Unlock()

	if dlc.tcpConn == nil {
		return "", fmt.Errorf("TCP connection not established")
	}

	dlc.tcpConn.SetReadDeadline(time.Now().Add(dlc.readTimeout))
	reader := bufio.NewReader(dlc.tcpConn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return line, nil
}

func (dlc *DataLoggerConnection) SendCommand(command string) (string, error) {
	// Send command
	_, err := dlc.Write([]byte(command + "\n"))
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

func (dlc *DataLoggerConnection) KeepAlive(interval time.Duration, stopChan <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !dlc.IsConnected() {
				fmt.Println("Connection lost, attempting to reconnect...")
				dlc.Reconnect(3)
			} else {
				// Send ping or keepalive command
				_, err := dlc.Write([]byte("PING\n"))
				if err != nil {
					fmt.Printf("Keepalive failed: %v\n", err)
				}
			}
		case <-stopChan:
			return
		}
	}
}

func main() {
	tcpLogger := NewDataLoggerConnection("tcp", "192.168.4.1", "8080")

	if err := tcpLogger.Connect(); err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer tcpLogger.Close()

	fmt.Println("Connected to datalogger")

	response, err := tcpLogger.SendCommand("READ_ALL")
	if err != nil {
		fmt.Printf("Command failed: %v\n", err)
		return
	}

	fmt.Printf("Response: %s\n", response)

	stopChan := make(chan struct{})
	go tcpLogger.KeepAlive(30*time.Second, stopChan)

	time.Sleep(5 * time.Minute)

	close(stopChan)
}
