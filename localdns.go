package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type debugging int

var debug debugging

func (d debugging) Debugf(level int, format string, args ...interface{}) {
	if d < debugging(level) {
		return
	}
	log.Printf(format, args...)
}

func (d debugging) Printf(format string, args ...interface{}) {
	d.Debugf(1, format, args...)
}

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
		q.RecursionDesired = true
		debug.Debugf(2, "resolveA : q : %#+v", q)
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

	appendBogusFromRandomSearch()
}

func appendBogusFromRandomSearch() {
	seen := map[string]bool{}
	for _, ip := range bogusIPs {
		seen[ip.String()] = true
	}

	known := len(seen)

	for l := 7; l <= 9; l++ {
		host := ""
		for len(host) < l {
			host += string(rune('a' + rand.Intn('z'-'a')))
		}
		for _, rr := range resolveA(dotted(host), "udp4") {
			if a, isA := rr.(*dns.A); isA {
				_, already := seen[a.A.String()]
				if !already {
					bogusIPs = append(bogusIPs, a.A)
					seen[a.A.String()] = true
				}
				log.Printf("Random host %s => IP %s", host, a.A)
			}
		}
	}

	if len(seen) > known {
		for i := known; i < len(bogusIPs); i++ {
			log.Printf("New bogus IP found: %s", bogusIPs[i])
		}
	} else {
		log.Println("No new bogus IPs discovered")
	}
}

func isBogus(r dns.RR) bool {
	a, isA := r.(*dns.A)
	if !isA {
		return false
	}

	for _, ip := range bogusIPs {
		if ip.Equal(a.A) {
			debug.Printf("Bogus (Verizon) IP: %s => %s", ip, a.Hdr.Name)
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

type responder func(dns.ResponseWriter, *dns.Msg)

func cnameResponder(mapper func(string) string) responder {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		reqName := req.Question[0].Name
		target := mapper(reqName)

		m := new(dns.Msg)
		m.SetReply(req)

		r := new(dns.CNAME)
		r.Hdr = dns.RR_Header{
			Name:   reqName,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    60,
		}
		r.Target = target
		m.Answer = append(m.Answer, r)

		answers := resolveA(target, protoFor(w.RemoteAddr()))
		m.Answer = append(m.Answer, answers...)

		w.WriteMsg(m)
	}
}

func constantCNAME(src, target string) responder {
	log.Printf("Mapping *.%s CNAME %s\n", src, target)
	return cnameResponder(func(local string) string {
		return target
	})
}

func mapCNAME(template, local string) string {
	return dotted(strings.Join(strings.Split(template, "%s"), local))
}

func mappedCNAME(src, dst string) responder {
	srcLabels := dns.SplitDomainName(src)
	return cnameResponder(func(reqName string) string {
		reqLabels := dns.SplitDomainName(reqName)
		lastLocal := len(reqLabels) - len(srcLabels)
		target := mapCNAME(dst, strings.Join(reqLabels[:lastLocal], "."))
		log.Printf("CNAMEMAP(%s:%s): %s -> %s", src, dst, reqName, target)
		return target
	})
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

type answeradder func(*dns.Msg, string, net.IP)

// If the IP is representable as IPv4, add an `A` record. Otherwise, if it is
// representable as IPv6, add an `AAAA` record.
func addAnswer(msg *dns.Msg, name string, ip net.IP) {
	if ip.To4() != nil {
		debug.Debugf(2, "addAnswer : %s -> A[%s]", name, ip)
		appendRR(msg, aRecord(name, ip))
	} else if ip.To16() != nil {
		debug.Debugf(2, "addAnswer : %s -> AAAA[%s]", name, ip)
		appendRR(msg, aaaaRecord(name, ip))
	} else {
		debug.Printf(" !(IPv4 || IPv6): %s -> %v\n", name, ip)
	}
}

func addAnswerOnly4(msg *dns.Msg, name string, ip net.IP) {
	if ip.To4() != nil {
		appendRR(msg, aRecord(name, ip))
	} else {
		debug.Printf(" !IPv4: %s -> %v\n", name, ip)
	}
}

func rrHeader(name string, rtype uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{
		Name:   name,
		Rrtype: rtype,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}
}

func aRecord(name string, ip net.IP) *dns.A {
	return &dns.A{
		Hdr: rrHeader(name, dns.TypeA, 60),
		A:   ip.To4(),
	}
}

func aaaaRecord(name string, ip net.IP) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  rrHeader(name, dns.TypeAAAA, 60),
		AAAA: ip.To16(),
	}
}

func srvRecord(name string, priority, weight, port uint16, target string) *dns.SRV {
	return &dns.SRV{
		Hdr:      rrHeader(name, dns.TypeSRV, 60),
		Priority: priority,
		Weight:   weight,
		Port:     port,
		Target:   target,
	}
}

func appendRR(msg *dns.Msg, rr dns.RR) {
	msg.Answer = append(msg.Answer, rr)
}

func selfAddressed(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	for _, ip := range findMyIP() {
		addAnswer(m, req.Question[0].Name, ip)
	}

	w.WriteMsg(m)
}

func ifaddr(adder answeradder, ifnames ...string) responder {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		for _, ifname := range ifnames {
			ifi, err := net.InterfaceByName(ifname)
			if err != nil {
				debug.Printf(" Interface(%s) err: %v\n", ifname, err)
				continue
			}
			addrs, err := ifi.Addrs()
			if err != nil {
				debug.Printf(" Interface(%s).Addrs() err: %v\n", ifname, err)
				continue
			}
			for _, addr := range addrs {
				debug.Printf(" IFI(%s) -> %v\n", ifname, addr)
				network, valid := addr.(*net.IPNet)
				if !valid {
					debug.Printf(" !IP: %v\n", addr)
					continue
				}
				adder(m, req.Question[0].Name, network.IP)
			}
		}
		w.WriteMsg(m)
	}
}

func loopback(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	addAnswer(m, req.Question[0].Name, net.ParseIP("127.0.0.1"))
	w.WriteMsg(m)
}

type dockerNetwork struct {
	Name, Id   string
	Containers map[string]dockerNetworkHost
}

type dockerNetworkHost struct {
	Name        string
	IPv4Address string
	IPv6Address string
}

type dockerContainer struct {
	Id              string
	State           dockerStatus
	NetworkSettings dockerContainerNetworkSettings
}

type dockerStatus struct {
	Status  string
	Running bool
}

type dockerContainerNetworkSettings struct {
	// TODO: I only use one, scalar field. Any way to un-nest this?
	IPAddress string
}

// TODO: more general support for DOCKER_HOST
type dockerDialer struct {
	filename string
}

func (d *dockerDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, "unix", d.filename)
}

var isDockerTLD = map[string]bool{}

func dockerAPI(path string) ([]byte, error) {
	onlyDocker := (&dockerDialer{"/var/run/docker.sock"}).DialContext
	client := &http.Client{Transport: &http.Transport{DialContext: onlyDocker}}
	res, err := client.Get(fmt.Sprintf("http://docker%s", path))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return ioutil.ReadAll(res.Body)
}

func dockerGetContainer(name string) (container dockerContainer, err error) {
	path := fmt.Sprintf("/containers/%s/json", name)
	var body []byte
	body, err = dockerAPI(path)
	if err == nil {
		err = json.Unmarshal(body, &container)
	}
	if container.Id == "" {
		err = fmt.Errorf("Docker container %s not found", name)
	}
	return container, err
}

func dockerGetAll() (hosts []dockerNetworkHost, err error) {
	// To list all: get network names, then containers per-network
	var networks []dockerNetwork
	var body []byte
	body, err = dockerAPI("/networks")
	if err == nil {
		if err = json.Unmarshal(body, &networks); err == nil {
			for _, network := range networks {
				body, err = dockerAPI(fmt.Sprintf("/networks/%s", network.Name))
				if err != nil {
					break
				}
				var network dockerNetwork
				if err = json.Unmarshal(body, &network); err != nil {
					break
				}
				for _, host := range network.Containers {
					hosts = append(hosts, host)
				}
			}
		}
	}
	return hosts, err
}

func dockerList(w dns.ResponseWriter, req *dns.Msg, strip int) {
	m := new(dns.Msg)
	m.SetReply(req)
	labels := dns.SplitDomainName(req.Question[0].Name)
	qName := dotted(strings.Join(labels[strip:], "."))
	if hosts, err := dockerGetAll(); err == nil {
		for _, host := range hosts {
			name := dotted(fmt.Sprintf("%s.%s", host.Name, qName))
			for _, addr := range []string{host.IPv4Address, host.IPv6Address} {
				if addr == "" {
					continue
				}
				var ip net.IP
				ip, _, err = net.ParseCIDR(addr)
				if err == nil {
					addAnswer(m, name, ip)
				}
			}
		}
	}
	w.WriteMsg(m)
}

func dockerResolve(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	labels := dns.SplitDomainName(req.Question[0].Name)
	host, tld := "", ""
	isDocker := false
	for i, label := range labels {
		host = label
		tld = strings.Join(labels[i+1:], ".")
		if isDockerTLD[dotted(tld)] {
			isDocker = true
			break
		}
	}
	if isDocker {
		info, err := dockerGetContainer(host)
		if err == nil {
			if info.State.Status == "" || info.State.Running {
				addr := info.NetworkSettings.IPAddress
				if addr != "" {
					addAnswer(m, req.Question[0].Name, net.ParseIP(addr))
				}
			}
		} else {
			debug.Printf("dockerGetContainer(%s): %v", host, err)
		}
	}
	w.WriteMsg(m)
}

func docker(w dns.ResponseWriter, req *dns.Msg) {
	q := req.Question[0]
	listAll := q.Qtype == dns.TypeSRV
	strip := 0
	labels := dns.SplitDomainName(q.Name)
	if isDockerTLD[q.Name] {
		listAll = true
	} else if labels[0] == "*" || labels[0][0] == '_' {
		listAll = true
		strip = 1
	}
	if listAll {
		dockerList(w, req, strip)
	} else {
		dockerResolve(w, req)
	}
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

func upstreamFromEnv(name string) (servers []string) {
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
			if strings.HasSuffix(name, "."+dmatch) || name == dmatch {
				match = true
				break
			}
		}

		if match {
			servers = append(servers, strings.Split(server, ",")...)
		}
	}
	return servers
}

func upstreamFromConfig() (servers []string) {
	// from skydns1/server/server.go
	config, err := dns.ClientConfigFromFile(resolvConf())
	if err == nil {
		for _, server := range config.Servers {
			servers = append(servers, net.JoinHostPort(server, config.Port))
		}
	}

	return servers
}

func upstreamFor(name string) (servers []string) {
	addresses := upstreamFromEnv(name)
	if len(addresses) == 0 {
		addresses = append(addresses, upstreamFromConfig()...)
	}
	for _, addr := range addresses {
		_, _, err := net.SplitHostPort(addr)
		if err != nil {
			addr = net.JoinHostPort(addr, "53")
		}
		servers = append(servers, addr)
	}
	debug.Printf("upstreamFor(%v) -> %v\n", name, servers)
	return servers
}

// adapted from skydns1/server/server.go#ServeDNSForward
func forward(w dns.ResponseWriter, req *dns.Msg) {
	debug.Printf("Q[%v] from[%v]\n", req.Question[0].Name, w.RemoteAddr())
	servers := upstreamFor(req.Question[0].Name)
	debug.Debugf(2, "forward : servers : %q", servers)
	if len(servers) == 0 {
		debug.Printf("forward : len(servers) == 0")
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
		debug.Debugf(2, "forward : server : %s", server)
		res, _, err := client.Exchange(req, server)
		if err == nil {
			allBogus, nonBogus := filterBogus(res.Answer)
			res.Answer = nonBogus
			if allBogus {
				res.SetRcode(req, dns.RcodeNameError)
			}
			for _, rr := range res.Answer {
				var dbgOut string
				switch t := rr.(type) {
				case *dns.A:
					dbgOut = fmt.Sprintf("A[%s]", t.A)
				case *dns.AAAA:
					dbgOut = fmt.Sprintf("AAAA[%s]", t.AAAA)
				default:
					dbgOut = fmt.Sprintf("%v", rr)
				}
				debug.Printf("from [%s] : %s", server, dbgOut)
			}
			w.WriteMsg(res)
			return
		}
		debug.Printf(" <- ERR: %v\n", err)
	}

	m := new(dns.Msg)
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeServerFailure)
	w.WriteMsg(m)
}

func setupDebug() {
	env := os.Getenv("DEBUG")
	if n, err := strconv.Atoi(env); err == nil {
		debug = debugging(n)
	} else if env != "" {
		debug = 1
	}
}

func setupCnames() {
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
}

func setupCnameMap() {
	for _, mapping := range strings.Split(os.Getenv("CNAMEMAP"), ",") {
		if mapping == "" {
			continue
		}
		parts := strings.Split(mapping, ":")
		if len(parts) != 2 {
			log.Fatalf("Bad CNAMEMAP value: no source TLD: %s", mapping)
		}
		src, dst := dotted(parts[0]), parts[1]
		sub := "{{host}}"
		log.Printf("Mapping *.%s.%s to %s", sub, src, mapCNAME(dst, sub))
		dns.HandleFunc(src, mappedCNAME(src, dst))
	}
}

func setupSelf() {
	for _, self := range strings.Split(os.Getenv("SELF"), ",") {
		if len(self) == 0 {
			continue
		}
		log.Printf("Mapping *.%s to own IP", dotted(self))
		dns.HandleFunc(dotted(self), selfAddressed)
	}
}

func setupIface() {
	for _, iface := range strings.Split(os.Getenv("IFACE"), ",") {
		if iface == "" {
			continue
		}
		parts := strings.Split(iface, "%")
		logErr := func() {
			log.Printf("IFACE should be of the form: domain%%iface1%%iface2")
		}
		if len(parts) < 2 {
			logErr()
			continue
		}
		dmatch := dotted(parts[0])
		ifnames := []string{}
		adder := addAnswer
		for _, ifname := range parts[1:] {
			if ifname == "4" || ifname == "only4" {
				adder = addAnswerOnly4
				debug.Printf("Only returning A records for %s\n", dmatch)
				continue
			}
			ifnames = append(ifnames, ifname)
		}
		if len(ifnames) == 0 {
			logErr()
			continue
		}
		log.Printf("Mapping *.%s to IP(s) of interfaces %v", dmatch, ifnames)
		dns.HandleFunc(dmatch, ifaddr(adder, ifnames...))
	}
}

func setupLoop() {
	for _, self := range strings.Split(os.Getenv("LOOP"), ",") {
		if len(self) == 0 {
			continue
		}
		log.Printf("Mapping *.%s to 127.0.0.1", dotted(self))
		dns.HandleFunc(dotted(self), loopback)
	}
}

func setupDocker() {
	for _, tld := range strings.Split(os.Getenv("DOCKER"), ",") {
		if tld == "" {
			continue
		}
		log.Printf("Serving Docker hosts on .%s", dotted(tld))
		dns.HandleFunc(dotted(tld), docker)
		isDockerTLD[dotted(tld)] = true
	}
}

func usage() {
	fmt.Println(strings.TrimSpace(`
localdns accepts no commandline arguments.

Config vars:
    ADDR= ip:port
    BOGUS= ip [ ,ip ]*
    CNAMEMAP= tld:template [ ,tld:template ]*
    CNAMES= tld:host [ ,tld:host ]*
    DEBUG= (any non-empty value = active)
    DOCKER= tld,...
    IFACE= tld%iface [ %iface ]* [ ,tld%iface [ %iface ]* ]*
    LOOP= tld [ ,tld ]*
    PORT= port
    RESOLV= filename
    SELF= tld [ ,tld ]*
    SERVERS= [ tld/ ]* host [ , [ tld/ ]* host ]*
`))
	os.Exit(0)
}

func main() {
	if len(os.Args) > 1 {
		usage()
	}

	setupDebug()
	setupCnames()
	setupCnameMap()
	setupSelf()
	setupIface()
	setupLoop()
	setupDocker()

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

	serve6 := addr[0] == ':'

	go serveDNS("tcp4", addr)
	go serveDNS("udp4", addr)
	if serve6 {
		go serveDNS("tcp6", addr)
		go serveDNS("udp6", addr)
	}

	select {}
}
