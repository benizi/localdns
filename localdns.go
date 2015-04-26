package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func protoFor(addr net.Addr) string {
	if _, isTCP := addr.(*net.TCPAddr); isTCP {
		return "tcp"
	}
	return "udp"
}

func resolveA(name, proto string) (answers []dns.RR) {
	client := &dns.Client{Net: proto, ReadTimeout: 5 * time.Second}
	for _, server := range upstreamFor(name) {
		q := new(dns.Msg)
		q.Question = make([]dns.Question, 1)
		q.Question[0] = dns.Question{name, dns.TypeA, uint16(dns.ClassINET)}
		q.Id = dns.Id()
		res, _, err := client.Exchange(q, server)
		if err == nil {
			answers = append(answers, res.Answer...)
		}
	}
	return answers
}

var bogusIPs []net.IP

func initBogus() {
	env := os.Getenv("BOGUS")
	for _, ip := range strings.Split(env, ",") {
		if len(ip) != 0 {
			log.Printf("Adding %s as a bogus IP", ip)
			bogusIPs = append(bogusIPs, net.ParseIP(ip))
		}
	}
}

func isBogus(r dns.RR) bool {
	a, isA := r.(*dns.A)
	if !isA {
		return false
	}

	for _, ip := range bogusIPs {
		if ip.Equal(a.A) {
			log.Printf("Bogus (Verizon) IP: %s => %s", ip, a.Hdr.Name)
			return true
		}
	}

	return false
}

func filterBogus(answers []dns.RR) (allBogus bool, nonBogus []dns.RR) {
	for _, answer := range answers {
		if !isBogus(answer) {
			nonBogus = append(nonBogus, answer)
		}
	}
	allBogus = (len(answers) != 0 && len(nonBogus) == 0)
	return allBogus, nonBogus
}

func constantCNAME(src, target string) func(dns.ResponseWriter, *dns.Msg) {
	log.Printf("Mapping *.%s CNAME %s\n", src, target)
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		r := new(dns.CNAME)
		r.Hdr = dns.RR_Header{
			Name: req.Question[0].Name,
			Rrtype: dns.TypeCNAME,
			Class: dns.ClassINET,
			Ttl: 60,
		}
		r.Target = target
		m.Answer = append(m.Answer, r)

		answers := resolveA(target, protoFor(w.RemoteAddr()))
		m.Answer = append(m.Answer, answers...)

		w.WriteMsg(m)
	}
}

func dotted(name string) (withDot string) {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func acceptableIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return false
	}
	if ip.To4() == nil {
		return false
	}
	return true
}

func findMyIP() (ips []net.IP) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}

	for _, addr := range addrs {
		network, ok := addr.(*net.IPNet)
		if !ok {
			log.Printf("Not ok: addr:[%v](%T) tcp:[%v]\n", addr, addr, network)
			continue
		}

		ip := network.IP
		if acceptableIP(ip) {
			ips = append(ips, ip)
		}
	}

	return ips
}

func addAnswer(msg *dns.Msg, name string, ip net.IP) {
	r := new(dns.A)
	r.Hdr = dns.RR_Header{
		Name: name,
		Rrtype: dns.TypeA,
		Class: dns.ClassINET,
		Ttl: 60,
	}
	r.A = ip.To4()
	msg.Answer = append(msg.Answer, r)
}

func selfAddressed(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	for _, ip := range findMyIP() {
		addAnswer(m, req.Question[0].Name, ip)
	}

	w.WriteMsg(m)
}

func loopback(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	addAnswer(m, req.Question[0].Name, net.ParseIP("127.0.0.1"))
	w.WriteMsg(m)
}

func serveDNS(proto string, addr string) {
	log.Printf("Serving DNS over %s on %s\n", proto, addr)
	log.Fatal(dns.ListenAndServe(addr, proto, nil))
}

func resolvConf() string {
	file := os.Getenv("RESOLV")
	if len(file) != 0 {
		return file
	}
	return "/etc/resolv.conf"
}

func upstreamFor(name string) (servers []string) {
	env := os.Getenv("SERVERS")
	for _, spec := range strings.Split(env, ",") {
		if len(spec) == 0 {
			continue
		}
		matchers := strings.Split(spec, "/")
		server, matchers := matchers[len(matchers)-1], matchers[:len(matchers)-1]
		match := len(matchers) == 0

		for _, matcher := range matchers {
			dmatch := dotted(matcher)
			if strings.HasSuffix(name, "." + dmatch) || name == dmatch {
				match = true
				break
			}
		}

		if match {
			servers = append(servers, strings.Split(server, ",")...)
		}
	}

	if len(servers) > 0 {
		return servers
	}

	// from skydns1/server/server.go
	config, err := dns.ClientConfigFromFile(resolvConf())
	if err == nil {
		for _, server := range config.Servers {
			servers = append(servers, net.JoinHostPort(server, config.Port))
		}
	}

	return servers
}

// adapted from skydns1/server/server.go#ServeDNSForward
func forward(w dns.ResponseWriter, req *dns.Msg) {
	servers := upstreamFor(req.Question[0].Name)
	if len(servers) == 0 {
		m := new(dns.Msg)
		m.SetReply(req)
		m.SetRcode(req, dns.RcodeServerFailure)
		m.Authoritative = false
		m.RecursionAvailable = true
		w.WriteMsg(m)
		return
	}

	client := &dns.Client{Net: protoFor(w.RemoteAddr()), ReadTimeout: 5 * time.Second}
	for _, server := range servers {
		res, _, err := client.Exchange(req, server)
		if err == nil {
			allBogus, nonBogus := filterBogus(res.Answer)
			res.Answer = nonBogus
			if allBogus {
				res.SetRcode(req, dns.RcodeNameError)
			}
			w.WriteMsg(res)
			return
		}
	}

	m := new(dns.Msg)
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeServerFailure)
	w.WriteMsg(m)
}

func main() {
	cnames := strings.Split(os.Getenv("CNAMES"), ",")
	for _, item := range cnames {
		if len(item) == 0 {
			continue
		}
		srcTarget := strings.Split(item, ":")
		src := dotted(srcTarget[0])
		target := dotted(srcTarget[1])
		dns.HandleFunc(src, constantCNAME(src, target))
	}

	for _, self := range strings.Split(os.Getenv("SELF"), ",") {
		if len(self) == 0 {
			continue
		}
		log.Printf("Mapping *.%s to own IP", dotted(self))
		dns.HandleFunc(dotted(self), selfAddressed)
	}

	for _, self := range strings.Split(os.Getenv("LOOP"), ",") {
		if len(self) == 0 {
			continue
		}
		log.Printf("Mapping *.%s to 127.0.0.1", dotted(self))
		dns.HandleFunc(dotted(self), loopback)
	}

	initBogus()

	dns.HandleFunc(".", forward)

	addr := os.Getenv("ADDR")
	if len(addr) == 0 {
		port := os.Getenv("PORT")
		if len(port) > 0 && strings.Contains(port, ":") {
			addr = port
		} else if len(port) > 0 {
			addr = fmt.Sprintf(":%s", port)
		} else {
			addr = ":9753"
		}
	}

	go serveDNS("tcp4", addr)
	go serveDNS("udp4", addr)

	select {}
}
