package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const (
    // Switch to 5223 once we implement the SSL server socket
    SERVER_PORT = "5222"
    // Listen on IPV4. Kik requires IPV4 so it should be no issue
    SERVER_TYPE = "tcp4" 
    // Client has this long to prove itself
    CLIENT_INITIAL_READ_TIMEOUT_SECONDS = 2
    // After initial read, abort if no data from client after this many seconds
    CLIENT_READ_TIMEOUT_SECONDS = 30

    CUSTOM_BANNER = false

    // Host from 15.59.x on Android. All of them resolve to the same IPs, but we will use a newer version anyway
    KIK_HOST = "talk15590an.kik.com"
    // Kik has 443 and 5223 open, both behave identically
    KIK_PORT = "443"
    // Kik uses TCP
    KIK_SERVER_TYPE = "tcp"
    // Kik shouldn't take longer than 5s to respond. If it does, abort
    KIK_INITIAL_READ_TIMEOUT_SECONDS = 5
    // After initial read, abort if no data from Kik after this many seconds
    KIK_READ_TIMEOUT_SECONDS = 30
)

func main() {
    server, err := net.Listen(SERVER_TYPE, ":" + SERVER_PORT)
    if err != nil {
        fmt.Println("Error opening socket:", err.Error())
        os.Exit(1)
    }
    defer server.Close()
    fmt.Println("Listening on :" + SERVER_PORT)
    for {
        connection, err := server.Accept()
        if err != nil {
            fmt.Println("Error accepting: ", err.Error())
        } else {
            go handleNewConnection(connection)
        }
    }
}

func handleNewConnection(clientConn net.Conn) {
    ipAddress, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
    if err != nil {
        // Shouldn't happen but being safe
        fmt.Println("Rejecting connection, could not parse remote IP address")
        clientConn.Close()
        return
    }

    k, err := readKFromClient(clientConn)
    if err != nil {
        // TODO: ban hosts
        fmt.Println("Rejecting from " + ipAddress + ": " + fmt.Sprint(err))
        clientConn.Close()
        return
    }
    err = k.verify()
    if err != nil {
        // TODO: ban hosts
        fmt.Println("Failed validation " + ipAddress + ": " + fmt.Sprint(err))
        clientConn.Close()
        return
    }

    fmt.Println("Accepting from " + ipAddress + ": " + k.RawStanza)
    kikConn, err := connectToKik(clientConn, k)
    if err != nil {
        fmt.Println("Failed to connect " + ipAddress + " to Kik: " + fmt.Sprint(err))
        clientConn.Close()
        return
    }

    go proxyClient("client", clientConn, *kikConn)
    proxyKik("kik", *kikConn, clientConn)
}

// Future implementations will unify proxyKik and proxyClient (as they will both be using TLS)
// We can also use the XmlPullParser to implement custom handling of stanzas.
// For now, both methods simply copy the packets to each others streams, making a blind proxy
// (past the initial stream tags)

func proxyKik(tag string, from tls.Conn, to net.Conn) {
    defer from.Close()
    defer to.Close()
    if _, err := io.Copy(&from, to); err != nil {}
}

func proxyClient(tag string, from net.Conn, to tls.Conn) {
    defer from.Close()
    defer to.Close()
    if _, err := io.Copy(from, &to); err != nil {}
}

func connectToKik(clientConn net.Conn, k *InitialStreamTag) (*tls.Conn, error) {
    var config tls.Config = tls.Config{ServerName: KIK_HOST}
    kikConn, err := tls.Dial(KIK_SERVER_TYPE, KIK_HOST + ":" + KIK_PORT, &config)
    if err != nil {
        return nil, err
    }
    kikConn.SetReadDeadline(time.Now().Add(CLIENT_READ_TIMEOUT_SECONDS * time.Second))
    kikConn.Write([]byte(k.RawStanza))
    kikResponse, err := readKFromKik(kikConn)
    if err != nil {
        return nil, err
    }
    clientConn.Write([]byte(kikResponse.generateServerResponse()))
    if !kikResponse.IsOk {
        return nil, errors.New("Kik rejected bind: " + kikResponse.RawStanza)
    }
    return kikConn, nil
}
