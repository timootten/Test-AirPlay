package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/grandcat/zeroconf"
)

func main() {
    // Get the hostname of the machine
    host, err := os.Hostname()
    if err != nil {
        log.Fatalf("Failed to get hostname: %v", err)
    }
    info := []string{
        "deviceid=00:05:CD:D4:42:38",
        "features=0x5A7FFFF7,0x1E",
        "model=AppleTV3,2",
        "pk=482131eacf7e006792da125540724283fb3f2ba6a25cabe13b5f1543b3b234bd",
        "pi=5e66cf9b-0a39-4e0c-9d32-081a8ce63231",
        "flags=0x4",
        "rmodel=PC1.0",
        "srcvers=220.68",
        "vv=2",
        "rrv=1.01",
        "rsv=1.00",
    }

    // Get all available IP addresses
    ifaces := getAllInterfaces()
    if len(ifaces) == 0 {
        log.Fatalf("No valid network interfaces found")
    }

    log.Printf("Hostname: %s", host)
    log.Printf("Network Interfaces: %v", ifaces)

    // Create a zeroconf service
    server, err := zeroconf.Register(
        "Test-AirPlay", // Service instance name
        "_airplay._tcp",    // Service type
        "local.",           // Service domain
        7000,               // Service port
        info,               // Service text records
        ifaces,             // Service interfaces
    )
    if err != nil {
        log.Fatalf("Failed to register zeroconf service: %v", err)
    }
    defer server.Shutdown()

    log.Println("Zeroconf service registered successfully. Press Ctrl+C to stop.")

    // Start TCP server
    //go startTCPServer(7000)

    // Handle termination signals to gracefully shut down the service
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    <-sig

    log.Println("Shutting down zeroconf service...")
    server.Shutdown()
    log.Println("Zeroconf service shut down successfully.")
}

// Helper function to get all IP addresses of the host
func getAllInterfaces() []net.Interface {
    var ifaces []net.Interface
    ifaces, err := net.Interfaces()
    if err != nil {
        log.Printf("Error fetching network interfaces: %v", err)
        return nil
    }
    for _, iface := range ifaces {
        // Skip interfaces that are down
        if iface.Flags&net.FlagUp == 0 {
            log.Printf("Skipping interface %v: interface is down", iface.Name)
            continue
        }
        addrs, err := iface.Addrs()
        if err != nil {
            log.Printf("Error fetching addresses for interface %v: %v", iface.Name, err)
            continue
        }
        for _, addr := range addrs {
            var ip net.IP
            switch v := addr.(type) {
            case *net.IPNet:
                ip = v.IP
            case *net.IPAddr:
                ip = v.IP
            }
            // Skip loopback or non-IPv4/IPv6 addresses
            if ip == nil || ip.IsLoopback() {
                log.Printf("Skipping address %v: loopback or invalid IP", ip)
                continue
            }
            log.Printf("Found valid IP address: %v", ip)
            ifaces = append(ifaces, iface)
        }
    }
    return ifaces
}

// Start a basic TCP server
func startTCPServer(port int) {
    listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
    if err != nil {
        log.Fatalf("Failed to start TCP server: %v", err)
    }
    defer listener.Close()

    log.Printf("TCP server listening on port %d", port)

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v", err)
            continue
        }

        go handleConnection(conn)
    }
}

// Handle incoming TCP connections
func handleConnection(conn net.Conn) {
    defer conn.Close()
    log.Printf("Accepted connection from %v", conn.RemoteAddr())

    // Simple echo server for demonstration
    buf := make([]byte, 1024)
    for {
        n, err := conn.Read(buf)
        if err != nil {
            log.Printf("Error reading from connection: %v", err)
            return
        }

        log.Printf("Received: %s", string(buf[:n]))

        _, err = conn.Write(buf[:n])
        if err != nil {
            log.Printf("Error writing to connection: %v", err)
            return
        }
    }
}