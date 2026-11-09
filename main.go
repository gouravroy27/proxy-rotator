package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Proxy struct {
	URL     *url.URL
	IsAlive bool
}

type Rotator struct {
	proxies   []*Proxy
	activeIdx int
	rrCounter int
	interval  time.Duration
	mu        sync.RWMutex
}

// bufferedConn keeps whatever bufio.Reader already read in memory
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func findProxyFile(name string) string {
	for _, p := range []string{name, "working-proxies.txt", "vpn/working-proxies.txt", "free-proxy-list.txt"} {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return name
}

func NewRotator(file string, interval time.Duration) (*Rotator, error) {
	path := findProxyFile(file)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open proxy file %s: %w", path, err)
	}
	defer f.Close()

	var proxies []*Proxy
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "://") {
			line = "socks5://" + line
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		proxies = append(proxies, &Proxy{URL: u, IsAlive: true})
	}

	if len(proxies) == 0 {
		return nil, errors.New("no valid proxies found in list")
	}

	log.Printf("Loaded %d proxies from %s", len(proxies), path)
	return &Rotator{proxies: proxies, interval: interval}, nil
}

// checkProxy tests if upstream can actually tunnel traffic
func checkProxy(p *Proxy) bool {
	conn, err := net.DialTimeout("tcp", p.URL.Host, 2500*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2500 * time.Millisecond))

	if p.URL.Scheme == "socks5" {
		if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
			return false
		}
		res := make([]byte, 2)
		if _, err := io.ReadFull(conn, res); err != nil || res[1] != 0 {
			return false
		}
		// Probe CONNECT to 1.1.1.1:80
		if _, err := conn.Write([]byte{5, 1, 0, 1, 1, 1, 1, 1, 0, 80}); err != nil {
			return false
		}
		hdr := make([]byte, 4)
		_, err = io.ReadFull(conn, hdr)
		return err == nil && hdr[1] == 0
	}

	// HTTP CONNECT probe
	fmt.Fprintf(conn, "CONNECT api.ipify.org:80 HTTP/1.1\r\nHost: api.ipify.org:80\r\nUser-Agent: curl/7.68.0\r\n\r\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	return err == nil && strings.Contains(line, "200")
}

func (r *Rotator) checkAll() {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 15) // limit concurrent probes
	for _, p := range r.proxies {
		wg.Add(1)
		go func(p *Proxy) {
			defer wg.Done()
			sem <- struct{}{}
			alive := checkProxy(p)
			<-sem

			r.mu.Lock()
			p.IsAlive = alive
			r.mu.Unlock()
		}(p)
	}
	wg.Wait()
}

func (r *Rotator) healthLoop(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.checkAll()
		}
	}
}

func (r *Rotator) rotateLoop(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.mu.Lock()
			n := len(r.proxies)
			if n > 0 {
				old := r.activeIdx
				for i := 1; i <= n; i++ {
					idx := (old + i) % n
					if r.proxies[idx].IsAlive {
						r.activeIdx = idx
						log.Printf("Rotated active proxy -> %s", r.proxies[idx].URL.String())
						break
					}
				}
			}
			r.mu.Unlock()
		}
	}
}

// getCandidate picks a healthy proxy, load-balancing bursts across alive nodes
func (r *Rotator) getCandidate(attempt int) *Proxy {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := len(r.proxies)
	if n == 0 {
		return nil
	}

	start := (r.activeIdx + r.rrCounter + attempt) % n
	r.rrCounter++

	for i := 0; i < n; i++ {
		idx := (start + i) % n
		if r.proxies[idx].IsAlive {
			return r.proxies[idx]
		}
	}
	return r.proxies[start]
}

func (r *Rotator) handleClient(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(60 * time.Second))

	// SOCKS5 greeting
	buf := make([]byte, 256)
	if _, err := io.ReadFull(client, buf[:2]); err != nil || buf[0] != 5 {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(client, buf[:nMethods]); err != nil {
		return
	}
	client.Write([]byte{5, 0}) // No auth

	// SOCKS5 request
	if _, err := io.ReadFull(client, buf[:4]); err != nil || buf[1] != 1 {
		client.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}) // only CONNECT supported
		return
	}

	var host string
	switch buf[3] {
	case 1: // IPv4
		if _, err := io.ReadFull(client, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 3: // Domain
		if _, err := io.ReadFull(client, buf[:1]); err != nil {
			return
		}
		d := make([]byte, buf[0])
		if _, err := io.ReadFull(client, d); err != nil {
			return
		}
		host = string(d)
	case 4: // IPv6
		if _, err := io.ReadFull(client, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		client.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(buf[:2])
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	// Failover loop
	var upstream net.Conn
	var chosen *Proxy
	for attempt := 0; attempt < 3; attempt++ {
		p := r.getCandidate(attempt)
		if p == nil {
			break
		}
		conn, err := r.dialUpstream(p, target)
		if err == nil {
			upstream = conn
			chosen = p
			break
		}
		r.mu.Lock()
		p.IsAlive = false
		r.mu.Unlock()
	}

	if upstream == nil {
		client.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}
	defer upstream.Close()

	log.Printf("[tunnel] %s -> %s via %s", client.RemoteAddr(), target, chosen.URL.String())
	client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) // Success

	client.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})

	// Relay data with half-close support
	go func() {
		io.Copy(upstream, client)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	io.Copy(client, upstream)
	if cw, ok := client.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

func (r *Rotator) dialUpstream(p *Proxy, target string) (net.Conn, error) {
	switch p.URL.Scheme {
	case "socks5":
		return dialSOCKS5(p.URL.Host, target)
	case "http":
		return dialHTTP(p.URL.Host, target)
	case "socks4":
		return dialSOCKS4(p.URL.Host, target)
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", p.URL.Scheme)
	}
}

func dialSOCKS5(proxyAddr, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 2500*time.Millisecond)
	if err != nil {
		return nil, err
	}

	// Auth greeting
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[1] != 0 {
		conn.Close()
		return nil, errors.New("socks5 handshake failed")
	}

	// Build connect payload
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)

	req := []byte{5, 1, 0}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 1)
		req = append(req, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		req = append(req, 4)
		req = append(req, ip6...)
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Read reply header
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("upstream connect rejected (code 0x%02x)", hdr[1])
	}

	// Drain bound address (RFC 1928) so leftover bytes don't corrupt stream
	var drainLen int
	switch hdr[3] {
	case 1:
		drainLen = 4 + 2
	case 4:
		drainLen = 16 + 2
	case 3:
		b := make([]byte, 1)
		if _, err := io.ReadFull(conn, b); err != nil {
			conn.Close()
			return nil, err
		}
		drainLen = int(b[0]) + 2
	}
	if _, err := io.CopyN(io.Discard, conn, int64(drainLen)); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func dialHTTP(proxyAddr, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 2500*time.Millisecond)
	if err != nil {
		return nil, err
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		conn.Close()
		return nil, fmt.Errorf("http connect failed: %s", strings.TrimSpace(line))
	}

	// Drain headers
	for {
		l, err := reader.ReadString('\n')
		if err != nil || l == "\r\n" || l == "\n" {
			break
		}
	}
	return &bufferedConn{Conn: conn, r: reader}, nil
}

func dialSOCKS4(proxyAddr, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 2500*time.Millisecond)
	if err != nil {
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)

	req := []byte{4, 1, byte(port >> 8), byte(port & 0xff)}
	ip := net.ParseIP(host).To4()
	if ip != nil {
		req = append(req, ip...)
	} else {
		req = append(req, 0, 0, 0, 1) // SOCKS4a
	}
	req = append(req, 0) // null user
	if ip == nil {
		req = append(req, []byte(host)...)
		req = append(req, 0)
	}

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil || resp[1] != 0x5a {
		conn.Close()
		return nil, errors.New("socks4 connect failed")
	}
	return conn, nil
}

func main() {
	file := flag.String("file", "", "proxy file (defaults to working-proxies.txt)")
	interval := flag.Duration("interval", 10*time.Second, "rotation interval")
	listen := flag.String("listen", "127.0.0.1:9050", "listen address")
	flag.Parse()

	r, err := NewRotator(*file, *interval)
	if err != nil {
		log.Fatalf("Init error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go r.healthLoop(ctx)
	go r.rotateLoop(ctx)

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("Listen error: %v", err)
	}
	log.Printf("Proxy Rotator listening on socks5://%s", *listen)

	go func() {
		for {
			client, err := l.Accept()
			if err != nil {
				return
			}
			go r.handleClient(client)
		}
	}()

	<-ctx.Done()
	l.Close()
	log.Println("Shutting down...")
}
