package main

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// ANSI 颜色定义
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorGray   = "\033[90m"
)

func main() {
	addr := ":7070"
	server := &http.Server{
		Addr:         addr,
		Handler:      http.HandlerFunc(handleRequest),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Printf(ColorGreen+"Starting proxy on %s"+ColorReset+"\n", addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf(ColorRed+"server failed: %v"+ColorReset, err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	clientAddr := r.RemoteAddr
	if clientAddr == "" {
		clientAddr = "unknown"
	}

	if strings.ToUpper(r.Method) == "CONNECT" {
		handleConnect(w, r, clientAddr)
		return
	}

	handleHTTP(w, r, clientAddr)
}

func handleHTTP(w http.ResponseWriter, r *http.Request, clientAddr string) {
	log.Printf(ColorGreen+"[HTTP] %s -> %s %s"+ColorReset, clientAddr, r.Method, r.URL.String())

	r.RequestURI = ""
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")

	transport := http.DefaultTransport
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "Error forwarding request: "+err.Error(), http.StatusBadGateway)
		log.Printf(ColorRed+"[HTTP] forward error: %v"+ColorReset, err)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)

	contentType := resp.Header.Get("Content-Type")
	if !isTextual(contentType) {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf(ColorRed+"[HTTP] read body error: %v"+ColorReset, err)
		} else {
			if !isXMLOrSVG(bodyBytes) {
				log.Printf(ColorGray+"[BODY] %s\n%s\n"+ColorReset, r.URL.String(), string(bodyBytes))
			}
			_, _ = w.Write(bodyBytes)
		}
	} else {
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			log.Printf(ColorRed+"[HTTP] copy body error: %v"+ColorReset, err)
		}
	}
}

func isTextual(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "text/css") ||
		strings.Contains(ct, "application/javascript") ||
		strings.Contains(ct, "text/javascript")
}

func isXMLOrSVG(b []byte) bool {
	s := bytes.TrimSpace(b)
	lower := strings.ToLower(string(s))
	return strings.HasPrefix(lower, "<?xml") ||
		strings.Contains(lower, "<svg")
}

func handleConnect(w http.ResponseWriter, r *http.Request, clientAddr string) {
	target := r.Host
	log.Printf(ColorBlue+"[CONNECT] %s -> %s"+ColorReset, clientAddr, target)

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
	defer clientConn.Close()

	serverConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		resp := "HTTP/1.1 502 Bad Gateway\r\n\r\n"
		clientConn.Write([]byte(resp))
		log.Printf(ColorRed+"[CONNECT] dial to target failed: %v"+ColorReset, err)
		return
	}
	defer serverConn.Close()

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf(ColorRed+"[CONNECT] write 200 failed: %v"+ColorReset, err)
		return
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(serverConn, clientBuf.Reader)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, serverConn)
		errc <- err
	}()
	<-errc
}
