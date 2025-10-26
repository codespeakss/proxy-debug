package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func main() {
	addr := ":7070" // 代理监听地址
	server := &http.Server{
		Addr:         addr,
		Handler:      http.HandlerFunc(handleRequest),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Printf("Starting proxy on %s\n", addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Log client remote and requested info
	clientAddr := r.RemoteAddr
	if clientAddr == "" {
		clientAddr = "unknown"
	}

	// If method is CONNECT -> tunnel (HTTPS)
	if strings.ToUpper(r.Method) == "CONNECT" {
		handleConnect(w, r, clientAddr)
		return
	}

	// Otherwise treat as regular HTTP request (proxy-style)
	handleHTTP(w, r, clientAddr)
}

func handleHTTP(w http.ResponseWriter, r *http.Request, clientAddr string) {
	// The incoming request to an explicit proxy contains the full URL in r.URL
	// Log the full URL
	log.Printf("[HTTP] %s -> %s %s", clientAddr, r.Method, r.URL.String())

	// Remove hop-by-hop headers that should not be sent by proxies
	// (simple cleaning)
	r.RequestURI = "" // required for client.Transport
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")

	// Use default transport to perform the request
	transport := http.DefaultTransport

	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "Error forwarding request: "+err.Error(), http.StatusBadGateway)
		log.Printf("[HTTP] forward error: %v", err)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy body
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("[HTTP] copy body error: %v", err)
	}
}

func handleConnect(w http.ResponseWriter, r *http.Request, clientAddr string) {
	// r.Host contains "host:port"
	target := r.Host
	log.Printf("[CONNECT] %s -> %s", clientAddr, target)

	// Hijack the connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	// ensure clientBuf is flushed/closed on return
	defer clientConn.Close()

	// Dial target
	serverConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		// Return 502 to client
		resp := "HTTP/1.1 502 Bad Gateway\r\n\r\n"
		clientConn.Write([]byte(resp))
		log.Printf("[CONNECT] dial to target failed: %v", err)
		return
	}
	// ensure serverConn closed on return
	defer serverConn.Close()

	// Send success response to client
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("[CONNECT] write 200 failed: %v", err)
		return
	}

	// Bidirectional copy
	// clientBuf is a *bufio.ReadWriter, so we need its Reader for copying
	errc := make(chan error, 2)

	go func() {
		_, err := io.Copy(serverConn, clientBuf.Reader)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, serverConn)
		errc <- err
	}()

	// wait for first error / EOF
	<-errc
	// Done; connections will be closed by deferred calls
}

