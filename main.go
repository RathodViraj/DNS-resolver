package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"resolver/cache"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const ROOT_SERVERS = "198.41.0.4,199.9.14.201,192.33.4.12,199.7.91.13,192.203.230.10,192.5.5.241,192.112.36.4,198.97.190.53,192.36.148.17,192.58.128.30,193.0.14.129,199.7.83.42,202.12.27.33"

func main() {
	debug := flag.Bool("debug", false, "enable debug logging")
	addr := flag.String("listen", ":53", "address to listen on (udp)")
	flag.Parse()

	if *debug {
		log.SetOutput(os.Stdout)
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
		log.Printf("debug logging enabled")
	} else {
		log.SetFlags(0)
		log.SetOutput(os.Stdout)
	}

	go cache.StartPeriodicCleanup()

	pc, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}
	defer pc.Close()

	buf := make([]byte, 4096)
	log.Printf("DNS resolver running on %s...", *addr)

	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}

		bufCopy := make([]byte, n)
		copy(bufCopy, buf[:n])
		go HandlePacket(pc, addr, bufCopy)
	}
}

func HandlePacket(pc net.PacketConn, addr net.Addr, buf []byte) {
	if err := handlePacketInternal(pc, addr, buf); err != nil {
		log.Printf("handlePacket error: %s", err)
	}
}

func handlePacketInternal(pc net.PacketConn, addr net.Addr, buf []byte) error {
	p := dnsmessage.Parser{}

	start := time.Now()

	header, err := p.Start(buf)
	if err != nil {
		return err
	}

	que, err := p.Question()
	if err != nil {
		return err
	}

	log.Printf("incoming query from %s: %s %s", addr.String(), que.Name.String(), que.Type.String())

	response, cacheType, cached := cache.GetFromCache(que.Name, que.Type)
	steps := 0

	if !cached {
		var dnsErr error
		response, steps, dnsErr = dnsQuery(getDNSServers(), que)
		err = dnsErr
		ttl := uint32(300)
		foundTTL := false
		for _, a := range response.Answers {
			if a.Header.Name.String() == que.Name.String() && a.Header.Type == que.Type {
				if !foundTTL || a.Header.TTL < ttl {
					ttl = a.Header.TTL
					foundTTL = true
				}
			}
		}
		if !foundTTL {
			for _, auth := range response.Authorities {
				if auth.Header.Type == dnsmessage.TypeNS {
					if !foundTTL || auth.Header.TTL < ttl {
						ttl = auth.Header.TTL
						foundTTL = true
					}
				}
			}
		}

		cache.SaveToCache(que.Name, que.Type, response, ttl)
		log.Printf("cache store: queries name=%s type=%s ttl=%d", que.Name.String(), que.Type.String(), ttl)

		for _, auth := range response.Authorities {
			if auth.Header.Type == dnsmessage.TypeNS {
				nsName := auth.Header.Name
				nsMsg := &dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Authorities: []dnsmessage.Resource{auth}}
				cache.SaveToCache(nsName, dnsmessage.TypeNS, nsMsg, auth.Header.TTL)
				log.Printf("cache store: ns name=%s ttl=%d", nsName.String(), auth.Header.TTL)
			}
		}

		for _, ans := range response.Answers {
			if ans.Header.Type == dnsmessage.TypeCNAME {
				cnameName := ans.Header.Name
				cnameMsg := &dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{ans}}
				cache.SaveToCache(cnameName, dnsmessage.TypeCNAME, cnameMsg, ans.Header.TTL)
				log.Printf("cache store: cname name=%s target=%v ttl=%d", cnameName.String(), ans.Body, ans.Header.TTL)
			}
		}

		for _, add := range response.Additionals {
			switch add.Header.Type {
			case dnsmessage.TypeA, dnsmessage.TypeAAAA:
				addName := add.Header.Name
				addMsg := &dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Additionals: []dnsmessage.Resource{add}}
				cache.SaveToCache(addName, add.Header.Type, addMsg, add.Header.TTL)
				log.Printf("cache store: glue name=%s type=%s ttl=%d", addName.String(), add.Header.Type.String(), add.Header.TTL)
			}
		}
	} else {
		log.Printf("cache hit (%s) name=%s type=%s", cacheType, que.Name.String(), que.Type.String())
	}

	if err != nil {
		resp := &dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       header.ID,
				Response: true,
				RCode:    dnsmessage.RCodeServerFailure,
			},
			Questions: []dnsmessage.Question{que},
		}
		response = resp
	}

	response.Header.ID = header.ID
	response.Header.Response = true

	if len(response.Questions) == 0 {
		response.Questions = []dnsmessage.Question{que}
	}

	if len(response.Answers) == 0 {
		response.Header.RCode = dnsmessage.RCodeServerFailure
	} else {
		response.Header.RCode = dnsmessage.RCodeSuccess
	}

	responseBuf, err := response.Pack()
	if err != nil {
		return err
	}

	_, err = pc.WriteTo(responseBuf, addr)
	duration := time.Since(start)
	log.Printf("Query metrics: name=%s type=%s duration=%s recursive_steps=%d", que.Name.String(), que.Type.String(), duration.String(), steps)
	return err
}

func dnsQuery(servers []net.IP, que dnsmessage.Question) (*dnsmessage.Message, int, error) {
	var finalAnswers []dnsmessage.Resource
	var lastResponse *dnsmessage.Message
	steps := 0

	for i := 0; i < 10; i++ {
		log.Println("Iteration =", i)

		steps++
		dnsAnswer, respServer, err := outgoingDnsQuery(servers, que)
		if err != nil {
			return nil, steps, err
		}

		lastResponse = dnsAnswer

		if respServer != nil {
			for idx, s := range servers {
				if s != nil && s.Equal(respServer) {
					servers[0], servers[idx] = servers[idx], servers[0]
					break
				}
			}
		}

		var cnameTarget *dnsmessage.Name

		for _, ans := range dnsAnswer.Answers {
			switch ans.Header.Type {
			case dnsmessage.TypeA, dnsmessage.TypeAAAA:
				finalAnswers = append(finalAnswers, ans)
			case dnsmessage.TypeCNAME:
				cnameTarget = &ans.Body.(*dnsmessage.CNAMEResource).CNAME
				finalAnswers = append(finalAnswers, ans)
			}
		}

		if dnsAnswer.Header.Authoritative && len(finalAnswers) > 0 && cnameTarget == nil {
			return &dnsmessage.Message{
				Header:      dnsAnswer.Header,
				Answers:     finalAnswers,
				Authorities: dnsAnswer.Authorities,
				Additionals: dnsAnswer.Additionals,
			}, steps, nil
		}

		if cnameTarget != nil {
			log.Printf("Following CNAME to %s", cnameTarget.String())
			que = dnsmessage.Question{Name: *cnameTarget, Type: que.Type, Class: dnsmessage.ClassINET}
			servers = getDNSServers()
			continue
		}

		nsNames := []string{}
		for _, auth := range dnsAnswer.Authorities {
			if auth.Header.Type == dnsmessage.TypeNS {
				nsNames = append(nsNames, auth.Body.(*dnsmessage.NSResource).NS.String())
			}
		}

		log.Printf("NS Records: %v", nsNames)

		glueServers := []net.IP{}
		for _, add := range dnsAnswer.Additionals {
			aName := normalizeDNSName(add.Header.Name.String())
			for _, ns := range nsNames {
				if aName == normalizeDNSName(ns) {
					switch add.Header.Type {
					case dnsmessage.TypeA:
						glueServers = append(glueServers, net.IP(add.Body.(*dnsmessage.AResource).A[:]))
					case dnsmessage.TypeAAAA:
						glueServers = append(glueServers, net.IP(add.Body.(*dnsmessage.AAAAResource).AAAA[:]))
					}
				}
			}
		}

		if len(glueServers) > 0 {
			log.Printf("Using GLUE servers: %v", glueServers)
			servers = glueServers
			continue
		}

		fallbackServers := []net.IP{}

		for _, ns := range nsNames {
			fqdn := normalizeDNSName(ns) + "."
			nsName, _ := dnsmessage.NewName(fqdn)

			nsQueA := dnsmessage.Question{Name: nsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
			respA, sA, _ := dnsQuery(getDNSServers(), nsQueA)
			steps += sA
			if respA != nil {
				for _, ans := range respA.Answers {
					if ans.Header.Type == dnsmessage.TypeA {
						fallbackServers = append(fallbackServers, net.IP(ans.Body.(*dnsmessage.AResource).A[:]))
					}
				}
			}

			nsQueAAAA := dnsmessage.Question{Name: nsName, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}
			respAAAA, sAAAA, _ := dnsQuery(getDNSServers(), nsQueAAAA)
			steps += sAAAA
			if respAAAA != nil {
				for _, ans := range respAAAA.Answers {
					if ans.Header.Type == dnsmessage.TypeAAAA {
						fallbackServers = append(fallbackServers, net.IP(ans.Body.(*dnsmessage.AAAAResource).AAAA[:]))
					}
				}
			}
		}

		if len(fallbackServers) > 0 {
			log.Printf("Resolved NS hostnames → using %v", fallbackServers)
			servers = fallbackServers
			continue
		}

		log.Println("No servers found → stopping iteration")
		break
	}

	if len(finalAnswers) > 0 {
		resp := &dnsmessage.Message{
			Header:  dnsmessage.Header{Response: true},
			Answers: finalAnswers,
		}
		if lastResponse != nil {
			resp.Authorities = lastResponse.Authorities
			resp.Additionals = lastResponse.Additionals
		}
		return resp, steps, nil
	}

	if lastResponse != nil {
		return &dnsmessage.Message{
			Header:      dnsmessage.Header{RCode: dnsmessage.RCodeServerFailure},
			Authorities: lastResponse.Authorities,
			Additionals: lastResponse.Additionals,
		}, steps, nil
	}

	return &dnsmessage.Message{Header: dnsmessage.Header{RCode: dnsmessage.RCodeServerFailure}}, steps, nil
}

func getDNSServers() []net.IP {
	rootservers := strings.Split(ROOT_SERVERS, ",")
	var servers []net.IP
	for _, s := range rootservers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		servers = append(servers, net.ParseIP(s))
	}
	return servers
}

func outgoingDnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Message, net.IP, error) {
	type queryResult struct {
		resp   *dnsmessage.Message
		server net.IP
		err    error
	}

	const maxParallel = 3
	perServerTimeout := 800 * time.Millisecond

	message := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       uint16(rand.Intn(65535)),
			Response: false,
		},
		Questions: []dnsmessage.Question{question},
	}

	reqBuf, err := message.Pack()
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resCh := make(chan queryResult, len(servers))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxParallel)
	var lastErr error
	var lastErrLock sync.Mutex

	for _, s := range servers {
		if s == nil {
			continue
		}
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(srv net.IP) {
			defer wg.Done()
			defer func() { <-sem }()

			d := net.Dialer{Timeout: 2 * time.Second}
			addr := srv.String() + ":53"
			log.Printf("sending hedged query to %s", addr)

			conn, err := d.DialContext(ctx, "udp", addr)
			if err != nil {
				lastErrLock.Lock()
				lastErr = err
				lastErrLock.Unlock()
				resCh <- queryResult{nil, srv, err}
				return
			}
			defer conn.Close()

			_ = conn.SetDeadline(time.Now().Add(perServerTimeout))

			if _, err := conn.Write(reqBuf); err != nil {
				lastErrLock.Lock()
				lastErr = err
				lastErrLock.Unlock()
				resCh <- queryResult{nil, srv, err}
				return
			}

			answer := make([]byte, 4096)
			n, err := bufio.NewReader(conn).Read(answer)
			if err != nil {
				lastErrLock.Lock()
				lastErr = err
				lastErrLock.Unlock()
				resCh <- queryResult{nil, srv, err}
				return
			}

			var p dnsmessage.Parser
			hdr, err := p.Start(answer[:n])
			if err != nil {
				lastErrLock.Lock()
				lastErr = err
				lastErrLock.Unlock()
				resCh <- queryResult{nil, srv, err}
				return
			}

			if err := p.SkipAllQuestions(); err != nil {
				lastErrLock.Lock()
				lastErr = err
				lastErrLock.Unlock()
				resCh <- queryResult{nil, srv, err}
				return
			}

			answers, _ := p.AllAnswers()
			authorities, _ := p.AllAuthorities()
			additionals, _ := p.AllAdditionals()

			resp := &dnsmessage.Message{
				Header:      hdr,
				Answers:     answers,
				Authorities: authorities,
				Additionals: additionals,
			}

			select {
			case resCh <- queryResult{resp, srv, nil}:
			case <-ctx.Done():
			}
		}(s)
	}

	go func() {
		wg.Wait()
		close(resCh)
	}()

	for r := range resCh {
		if r.err == nil && r.resp != nil {
			cancel()
			return r.resp, r.server, nil
		}
	}

	if lastErr != nil {
		return nil, nil, lastErr
	}
	return nil, nil, fmt.Errorf("no response from servers")
}

func normalizeDNSName(n string) string {
	n = strings.ToLower(n)
	n = strings.TrimSuffix(n, ".")
	return n
}
