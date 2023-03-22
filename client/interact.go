// dnstt-client is the client end of a DNS tunnel.
//
// Usage:
//
//	dnstt-client [-doh URL|-dot ADDR|-udp ADDR] -pubkey-file PUBKEYFILE DOMAIN LOCALADDR
//
// Examples:
//
//	dnstt-client -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
//	dnstt-client -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000
//
// The program supports DNS over HTTPS (DoH), DNS over TLS (DoT), and UDP DNS.
// Use one of these options:
//
//	-doh https://resolver.example/dns-query
//	-dot resolver.example:853
//	-udp resolver.example:53
//
// You can give the server's public key as a file or as a hex string. Use
// "dnstt-server -gen-key" to get the public key.
//
//	-pubkey-file server.pub
//	-pubkey 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// LOCALADDR is the TCP address that will listen for connections and forward
// them over the tunnel.
//
// In -doh and -dot modes, the program's TLS fingerprint is camouflaged with
// uTLS by default. The specific TLS fingerprint is selected randomly from a
// weighted distribution. You can set your own distribution (or specific single
// fingerprint) using the -utls option. The special value "none" disables uTLS.
//
//	-utls '3*Firefox,2*Chrome,1*iOS'
//	-utls Firefox
//	-utls none
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/eichgee/dnstt-android/dns"
	"github.com/eichgee/dnstt-android/noise"
	"github.com/eichgee/dnstt-android/turbotunnel"
	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/sys/unix"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

type Data struct {
	DohURL     string
	DotAddr    string
	UdpAddr    string
	ListenAddr string

	PubkeyFile       string
	PubkeyString     string
	UtlsDistribution string

	Domain string
}

type ProtectedDialer struct {
	currentServer string
	server        *resolved
	resolver      *net.Resolver
	log           Event
}

type Instance struct {
	data   *Data
	ln     *net.TCPListener
	dialer *ProtectedDialer

	log Event
}

type Event interface {
	Status(string)
	Protect(int) bool
}

type resolved struct {
	ip   net.IP
	port int
}

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	// Names must be 255 octets or shorter in total length.
	// https://tools.ietf.org/html/rfc1035#section-2.3.4
	capacity := 255
	// Subtract the length of the null terminator.
	capacity -= 1
	for _, label := range domain {
		// Subtract the length of the label and the length octet.
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64 bytes to
	// encode.
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

func (i *Instance) createConnection(utlsClientHelloID *utls.ClientHelloID, domain dns.Name) (net.Addr, net.PacketConn, error) {
	// Iterate over the remote resolver address options and select one and
	// only one.
	var remoteAddr net.Addr
	var pconn net.PacketConn
	var err error
	for _, opt := range []struct {
		s string
		f func(string) (net.Addr, net.PacketConn, error)
	}{
		// -doh
		{i.data.DohURL, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			var rt http.RoundTripper
			if utlsClientHelloID == nil {
				transport := &http.Transport{
					Dial:        i.dialer.Dial,
					DialContext: i.dialer.DialContext,
				}
				// Disable DefaultTransport's default Proxy =
				// ProxyFromEnvironment setting, for conformity
				// with utlsRoundTripper and with DoT mode,
				// which do not take a proxy from the
				// environment.
				transport.Proxy = nil
				rt = transport
			} else {
				rt = NewUTLSRoundTripper(nil, utlsClientHelloID, i.dialer)
			}
			pconn, err := NewHTTPPacketConn(rt, s, 32)
			return addr, pconn, err
		}},
		// -dot
		{i.data.DotAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
			if utlsClientHelloID == nil {
				dialTLSContext = (&tls.Dialer{
					NetDialer: &net.Dialer{
						Resolver: i.dialer.resolver,
					}}).DialContext
			} else {
				dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return i.dialer.utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
				}
			}

			pconn, err := NewTLSPacketConn(s, dialTLSContext)
			return addr, pconn, err
		}},
		// -udp
		{i.data.UdpAddr, func(s string) (net.Addr, net.PacketConn, error) {
			resolved, err := i.dialer.lookupAddr(s)
			if err != nil {
				return nil, nil, err
			}
			addr := &net.UDPAddr{IP: resolved.ip, Port: resolved.port}
			pconn, err := i.dialer.ListenUDP()
			return addr, pconn, err
		}},
	} {

		if opt.s == "" {
			continue
		}
		if pconn != nil {
			return nil, nil, fmt.Errorf("only one of -doh, -dot, and -udp may be given")
		}
		remoteAddr, pconn, err = opt.f(opt.s)
		if err != nil {
			return nil, nil, err
		}
		pconn = NewDNSPacketConn(pconn, remoteAddr, domain)
		return remoteAddr, pconn, err
	}
	return nil, nil, err
}

func (i *Instance) createSmuxSession(mtu int, pubkey []byte, clientHello *utls.ClientHelloID, domain dns.Name) (net.PacketConn, *kcp.UDPSession, *smux.Session, error) {
	remoteAddr, pconn, err := i.createConnection(clientHello, domain)
	if err != nil {
		return nil, nil, nil, err
	}
	// Open a KCP conn on the PacketConn.
	conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening KCP conn: %v", err)
	}
	// Permit coalescing the payloads of consecutive sends.
	conn.SetStreamMode(true)
	// Disable the dynamic congestion window (limit only by the maximum of
	// local and remote static windows).
	conn.SetNoDelay(
		0, // default nodelay
		0, // default interval
		0, // default resend
		1, // nc=1 => congestion window off
	)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if rc := conn.SetMtu(mtu); !rc {
		panic(rc)
	}

	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewClient(conn, pubkey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Start a smux session on the Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = 15 * time.Second
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening smux session: %v", err)
	}

	return pconn, conn, sess, err
}

func (i *Instance) handle(local *net.TCPConn, sess *smux.Session, conv uint32) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		if i.log != nil {
			i.log.Status(fmt.Sprintf("end stream %08x:%d", conv, stream.ID()))
		}
		log.Printf("end stream %08x:%d", conv, stream.ID())
		stream.Close()
	}()
	if i.log != nil {
		i.log.Status(fmt.Sprintf("begin stream %08x:%d", conv, stream.ID()))
	}
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			if i.log != nil {
				i.log.Status(fmt.Sprintf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err))
			}
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			if i.log != nil {
				i.log.Status(fmt.Sprintf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err))
			}
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return err
}

func (i *Instance) run(utlsClientHelloID *utls.ClientHelloID, pubkey []byte, domain dns.Name, localAddr *net.TCPAddr) error {
	var err error
	i.ln, err = net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}

	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1 // clientid + padding length prefix + padding + data length prefix
	if mtu < 80 {
		return fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
	}

	if i.log != nil {
		i.log.Status(fmt.Sprintf("effective MTU %d", mtu))
	}
	log.Printf("effective MTU %d", mtu)

	pconn, conn, sess, err := i.createSmuxSession(mtu, pubkey, utlsClientHelloID, domain)
	if err != nil {
		return err
	}

	var connLocker = new(sync.Mutex)

	log.Printf("begin session %08x", conn.GetConv())

	close := func() {
		log.Println("closing conn")
		if sess != nil {
			sess.Close()
		}

		if conn != nil {
			conn.Close()
		}

		if pconn != nil {
			pconn.Close()
		}
	}

	defer close()

	for {
		local, err := i.ln.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return nil
		}

		go func() {
			defer local.Close()

			if sess.IsClosed() {
				connLocker.Lock()
				defer connLocker.Unlock()

				close()
				
				pconn, conn, sess, err = i.createSmuxSession(mtu, pubkey, utlsClientHelloID, domain)
				if err != nil {
					log.Println("createSmuxSession: ", err)
					return
				}
			}

			err := i.handle(local.(*net.TCPConn), sess, conn.GetConv())
			if err != nil {
				if i.log != nil {
					i.log.Status(fmt.Sprintf("handle: %v", err))
				}
				log.Printf("handle: %v", err)
			}
		}()
	}
}

func (i *Instance) Start() error {
	if i.data.UtlsDistribution == "" {
		i.data.UtlsDistribution = "3*Firefox_65,1*Firefox_63,1*iOS_12_1"
	}

	domain, err := dns.ParseName(i.data.Domain)
	if err != nil {
		return fmt.Errorf("invalid domain %+q: %v", i.data.Domain, err)
	}
	localAddr, err := net.ResolveTCPAddr("tcp", i.data.ListenAddr)
	if err != nil {
		return errors.New(fmt.Sprint(err))
	}

	var pubkey []byte
	if i.data.PubkeyFile != "" && i.data.PubkeyString != "" {
		return fmt.Errorf("only one of -pubkey and -pubkey-file may be used")
	} else if i.data.PubkeyFile != "" {
		var err error
		pubkey, err = readKeyFromFile(i.data.PubkeyFile)
		if err != nil {
			return fmt.Errorf("cannot read pubkey from file: %v", err)
		}
	} else if i.data.PubkeyString != "" {
		var err error
		pubkey, err = noise.DecodeKey(i.data.PubkeyString)
		if err != nil {
			return fmt.Errorf("pubkey format error: %v", err)
		}
	}

	if len(pubkey) == 0 {
		return fmt.Errorf("the -pubkey or -pubkey-file option is required")
	}

	utlsClientHelloID, err := sampleUTLSDistribution(i.data.UtlsDistribution)
	if err != nil {
		return fmt.Errorf("parsing -utls: %v", err)
	}
	if utlsClientHelloID != nil {
		if i.log != nil {
			i.log.Status(fmt.Sprintf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version))
		}
		log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
	}

	for _, opt := range []struct {
		dnsAddr string
	}{
		{i.data.DohURL}, {i.data.DotAddr}, {i.data.UdpAddr},
	} {
		var (
			err          error
			host         string
			resolvedHost *resolved
		)
		if opt.dnsAddr == "" {
			continue
		}

		if strings.HasPrefix(opt.dnsAddr, "https://") {
			var url *url.URL
			url, err = url.Parse(opt.dnsAddr)
			if err != nil {
				log.Println(err)
			} else {
				s, err := addrForDial(url)
				if err != nil {
					log.Println(err)
				} else {
					host = s
					resolvedHost, err = i.dialer.lookupAddr(s)
					if err != nil {
						log.Println(err)
					}
				}
			}
		} else {
			host = opt.dnsAddr
			resolvedHost, err = i.dialer.lookupAddr(opt.dnsAddr)
		}

		if err != nil {
			return err
		}

		i.dialer.currentServer = host
		i.dialer.server = resolvedHost

		break
	}

	err = i.run(utlsClientHelloID, pubkey, domain, localAddr)
	if err != nil {
		return err
	}

	return nil
}

func (i *Instance) Stop() {
	if i.ln != nil {
		i.ln.Close()
		i.ln = nil
	}
}

func (i *Instance) SetData(d *Data) {
	i.data = d
}

func newProtectedDialer(ev Event) *ProtectedDialer {
	return &ProtectedDialer{
		resolver: &net.Resolver{PreferGo: false},
		log:      ev,
	}
}

func (d *ProtectedDialer) lookupAddr(addr string) (*resolved, error) {

	var (
		err        error
		host, port string
		portnum    int
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if host, port, err = net.SplitHostPort(addr); err != nil {
		log.Println("PrepareDomain SplitHostPort Error")
		return nil, err
	}

	if portnum, err = d.resolver.LookupPort(ctx, "tcp", port); err != nil {
		log.Println("PrepareDomain LookupPort Error")
		return nil, err
	}

	addrs, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("domain failed to resolve")
	}

	var ip net.IP
	for _, ia := range addrs {
		if ia.IP.To4() == nil {
			continue
		}
		ip = ia.IP
		break
	}

	if ip == nil {
		return nil, fmt.Errorf("domain failed to resolve to ipv4")
	}

	r := &resolved{
		ip:   ip,
		port: portnum,
	}

	return r, nil
}

func getFd(network string) (fd int, err error) {
	switch network {
	case "tcp":
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	case "udp":
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	default:
		err = fmt.Errorf("unknow network")
	}
	return
}

func (p *ProtectedDialer) DialContext(context context.Context, network, address string) (net.Conn, error) {
	log.Printf("dial, origin addr: %v, cached addr: %v\n, resolved: %v", address, p.currentServer, p.server)
	fd, err := getFd(network)

	if err != nil {
		return nil, err
	}

	defer unix.Close(fd)

	// call android VPN service to "protect" the fd connecting straight out
	p.log.Protect(fd)

	var resolved *resolved

	if strings.Compare(address, p.currentServer) == 0 && p.server != nil {
		log.Println("dial address is same, using dns cache")
		resolved = p.server
	} else {
		resolved, err = p.lookupAddr(address)
	}

	if err != nil {
		return nil, err
	}

	sa := &unix.SockaddrInet4{
		Port: resolved.port,
	}
	copy(sa.Addr[:], resolved.ip.To4())

	if err := unix.Connect(fd, sa); err != nil {
		log.Print("fdConn unix.Connect error")
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "Socket")
	if file == nil {
		// returned value will be nil if fd is not a valid file descriptor
		return nil, errors.New("fdConn fd invalid")
	}

	defer file.Close()
	//Closing conn does not affect file, and closing file does not affect conn.
	conn, err := net.FileConn(file)
	if err != nil {
		log.Print("fdConn FileConn Close Fd error")
		return nil, err
	}

	return conn, nil
}

func (p *ProtectedDialer) Dial(network, address string) (net.Conn, error) {
	return p.DialContext(context.Background(), network, address)
}

func (p *ProtectedDialer) ListenUDP() (net.PacketConn, error) {
	fd, err := getFd("udp")

	if err != nil {
		return nil, err
	}

	defer unix.Close(fd)

	// call android VPN service to "protect" the fd connecting straight out
	p.log.Protect(fd)

	file := os.NewFile(uintptr(fd), "Socket")
	if file == nil {
		// returned value will be nil if fd is not a valid file descriptor
		return nil, errors.New("fdConn fd invalid")
	}

	defer file.Close()
	//Closing conn does not affect file, and closing file does not affect conn.
	conn, err := net.FilePacketConn(file)
	if err != nil {
		log.Print("fdConn FileConn Close Fd error")
		return nil, err
	}

	return conn, nil
}

func New(event Event) *Instance {
	return &Instance{
		log:    event,
		dialer: newProtectedDialer(event),
	}
}
