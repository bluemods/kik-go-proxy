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
    SERVER_PORT = "5222" // Switch to 5223 once we implement the SSL server socket
    SERVER_TYPE = "tcp4"
    CLIENT_INITIAL_READ_TIMEOUT_SECONDS = 2
    CLIENT_READ_TIMEOUT_SECONDS = 60

    CUSTOM_BANNER = false

    KIK_HOST = "simplean.kik.com"
    KIK_PORT = "443"
    KIK_SERVER_TYPE = "tcp"
    KIK_INITIAL_READ_TIMEOUT_SECONDS = 5
    KIK_READ_TIMEOUT_SECONDS = 60
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
