package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
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
			answers = appendFiltered(answers, res.Answer...)
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

	go appendBogusFromRandomSearch()
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

var defaultAnswerAdder answeradder = addAnswer

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

func addAnswerOnly6(msg *dns.Msg, name string, ip net.IP) {
	if ip.To16() != nil {
		appendRR(msg, aaaaRecord(name, ip))
	} else {
		debug.Printf(" !IPv6: %s -> %v\n", name, ip)
	}
}

type answerfilter func(dns.RR) bool

var defaultAnswerFilter answerfilter = allowVersions(4, 6)

func allowVersions(versions ...int) answerfilter {
	allow4 := false
	allow6 := false
	for _, v := range versions {
		switch v {
		case 4:
			allow4 = true
		case 6:
			allow6 = true
		default:
			log.Fatalf("Unhandled IP version specified: %s", v)
		}
	}
	return func(rr dns.RR) bool {
		switch rr.(type) {
		case *dns.A:
			return allow4
		case *dns.AAAA:
			return allow6
		default:
			return true
		}
	}
}

func appendFiltered(answers []dns.RR, rrs ...dns.RR) []dns.RR {
	for _, a := range rrs {
		if defaultAnswerFilter(a) {
			answers = append(answers, a)
		}
	}
	return answers
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
		defaultAnswerAdder(m, req.Question[0].Name, ip)
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
	defaultAnswerAdder(m, req.Question[0].Name, net.ParseIP("127.0.0.1"))
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
	Name            string
	State           dockerStatus
	Config          dockerContainerConfig
	NetworkSettings dockerContainerNetworkSettings
}

type dockerStatus struct {
	Status  string
	Running bool
}

type dockerContainerConfig struct {
	Hostname string
	Compose  dockerComposeInfo `json:"Labels"`
	Cmd      []string
}

type dockerComposeInfo struct {
	Number  dockerComposeNumber  `json:"com.docker.compose.container-number"`
	Oneoff  dockerComposeBoolean `json:"com.docker.compose.oneoff"`
	Project string               `json:"com.docker.compose.project"`
	Service string               `json:"com.docker.compose.service"`
}

type dockerComposeNumber int

func parseJsonString(buf []byte) (string, error) {
	var ret string
	err := json.Unmarshal(buf, &ret)
	return ret, err
}

func (n *dockerComposeNumber) UnmarshalJSON(buf []byte) error {
	data := string(buf)
	var parsed int
	s, err := parseJsonString(buf)
	if err != nil {
		err = fmt.Errorf("dockerComposeNumber should be a JSON string")
		goto fail
	}
	parsed, err = strconv.Atoi(s)
	if err != nil {
		goto fail
	}
	*n = dockerComposeNumber(parsed)
	return nil
fail:
	return fmt.Errorf("dockerComposeNumber invalid input: %s (%v)", data, err)
}

func (n dockerComposeNumber) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%d"`, n)), nil
}

type dockerComposeBoolean bool

var dockerComposeBooleanStrings = map[string]dockerComposeBoolean{
	"True":  true,
	"False": false,
}

func (b *dockerComposeBoolean) UnmarshalJSON(buf []byte) error {
	var mapped dockerComposeBoolean
	var ok bool
	data := string(buf)
	s, err := parseJsonString(buf)
	if err != nil {
		err = fmt.Errorf("dockerComposeBoolean should be a JSON string")
		goto fail
	}
	mapped, ok = dockerComposeBooleanStrings[s]
	if !ok {
		err = fmt.Errorf("Unrecognized value: (%s)", s)
		goto fail
	}
	*b = mapped
	return nil
fail:
	err = fmt.Errorf("dockerComposeBoolean invalid input: %s (%v)", data, err)
	return err
}

func (b dockerComposeBoolean) MarshalJSON() ([]byte, error) {
	s := `"False"`
	if b {
		s = `"True"`
	}
	return []byte(s), nil
}

func (info dockerComposeInfo) isPresent() bool {
	return info.Project != "" && info.Service != ""
}

func (c dockerContainer) isComposed() bool {
	return c.Config.Compose.isPresent()
}

func (c dockerContainer) shortName() string {
	parts := strings.Split(c.Name, "/")
	if len(parts) == 2 && parts[0] == "" {
		return parts[1]
	}
	return ""
}

type dockerContainerNetworkSettings struct {
	IPAddress string
	Networks  map[string]dockerContainerNetwork
}

type dockerContainerNetwork struct {
	Aliases   []string
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
					defaultAnswerAdder(m, name, ip)
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
	var hostparts []string
	isDocker := false
	for i, _ := range labels {
		tld = strings.Join(labels[i+1:], ".")
		if !isDockerTLD[dotted(tld)] {
			continue
		}
		isDocker = true
		hostparts = labels[:i+1]
		break
	}
	if isDocker {
		for i := len(hostparts) - 1; i >= 0; i-- {
			host = strings.Join(hostparts[i:], ".")
			ids, found := containerByName.get(host)
			if !found {
				continue
			}
			for _, id := range ids {
				if entry, ok := containerInfo[id]; ok {
					for _, addr := range entry.addrs {
						ip := net.IP(addr)
						defaultAnswerAdder(m, req.Question[0].Name, ip)
					}
				}
			}
			break
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

type eventaction string

const (
	Connect    eventaction = "connect"
	Disconnect             = "disconnect"
)

type eventactor struct {
	ID         string
	Attributes map[string]string
}

type dockerevent struct {
	Action eventaction
	Actor  eventactor
	object map[string]interface{}
	raw    string
}

func dockerEventListener(restart chan bool) (chan dockerevent, error) {
	events := make(chan dockerevent, 1)
	args := []string{
		"events",
		"--format={{json .}}",
		"--filter=type=network",
		"--filter=event=connect",
		"--filter=event=disconnect",
	}
	cmd := exec.Command("docker", args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("Couldn't StdoutPipe: %v", err)
	}
	err = cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("Couldn't run docker events: %s", err)
	}
	decoder := json.NewDecoder(out)
	go func() {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				var evt dockerevent
				err := decoder.Decode(&evt.object)
				if err != nil {
					log.Fatalf("ERR: %#+v", err)
					break
				}
				debug.Debugf(2, "Incoming event: %#+v", evt)
				debug.Debugf(2, "Incoming event as JSON:\n%s", asJSON(evt.object))
				reJSONed, err := json.Marshal(evt.object)
				if err != nil {
					log.Fatalf("ERR: %#+v", err)
					break
				}
				err = json.NewDecoder(bytes.NewReader(reJSONed)).Decode(&evt)
				if err != nil {
					log.Fatalf("ERR: %#+v", err)
					break
				}
				debug.Printf("Specific event: %#+v", evt)
				events <- evt
			}
		}()
		wg.Wait()
		log.Print("cmd.Wait()")
		cmd.Wait()
		restart <- true
	}()
	return events, nil
}

func initDocker() {
	go listenDocker()
	go preloadDocker()
	go serveDockerWeb()
}

func listenDocker() {
	var events chan dockerevent
	restart := make(chan bool, 1)
	go func() {
		restart <- true
	}()
	for {
		select {
		case _, ok := <-restart:
			debug.Printf("listenDocker <-restart")
			if !ok {
				log.Fatal("<-restart was closed")
			}
			listener, err := dockerEventListener(restart)
			if err == nil {
				events = listener
			}
		case e, ok := <-events:
			debug.Printf("listenDocker <-events")
			if !ok {
				log.Fatal("<-events was closed")
			}
			processDockerEvent(e)
		}
	}
}

func preloadDocker() {
	cmd := exec.Command("docker", "ps", "-q", "--no-trunc")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	err = cmd.Start()
	if err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			id := scanner.Text()
			if id != "" {
				addContainerMappings(id)
			}
		}
	}()
	wg.Wait()
	cmd.Wait()
}

func serveDockerWeb() {
	host, port, err := net.SplitHostPort(os.Getenv("DOCKERHTTP"))
	if err != nil {
		return
	}
	http.HandleFunc("/c/", handleDockerWebContainer)
	http.HandleFunc("/", handleDockerWeb)
	go func() {
		addr := net.JoinHostPort(host, port)
		err = http.ListenAndServe(addr, nil)
		if err != nil {
			log.Printf("Error serving Docker web at %s: %v", addr, err)
		}
	}()
}

const (
	header = `<!DOCTYPE html>
<head>
<title>Docker info</title>
</head>
<body>
<h1>Docker info</h1>
<div id="info">
`
	footer = `</div>
</body>
</html>
`
)

func dockerWebSection(w http.ResponseWriter, name string, index multiset) {
	label := strings.ToLower(name)
	fmt.Fprintf(w, "<h2>By %s</h2>\n<div>\n", name)
	for _, n := range sortuniq(index.keys()) {
		fmt.Fprintf(w, "<div id=\"%s-%s\">%s</div>\n<blockquote>\n", label, n, n)
		for _, id := range sortuniq(index[n].values()) {
			fmt.Fprintf(w, "%s<br>\n", id)
		}
		io.WriteString(w, "</blockquote>\n")
	}
	io.WriteString(w, "</div>\n")
}

func handleDockerWeb(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, header)

	dockerWebSection(w, "Name", containerByName)
	dockerWebSection(w, "Network", containerByNetwork)
	dockerWebSection(w, "IP", containerByIP)

	var ids []string
	for k, _ := range containerInfo {
		ids = append(ids, k)
	}
	ids = sortuniq(ids)
	for _, id := range ids {
		fmt.Fprintf(w, "<div id=\"container-%s\">%s</div>\n<blockquote>\n", id, id)
		for _, n := range containerInfo[id].names {
			fmt.Fprintf(w, "%s<br>\n", n)
		}
		io.WriteString(w, "</blockquote>\n")
	}
	io.WriteString(w, "</div>\n")
	io.WriteString(w, footer)
}

func handleDockerWebContainer(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/c/")
	container, err := dockerGetContainer(id)
	if err != nil {
		fmt.Fprintf(w, "Failed to find container %s: %v\n", id, err)
		return
	}
	b, err := json.MarshalIndent(container, "", "  ")
	if err != nil {
		fmt.Fprintf(w, "Failed to print container %s: %v\n", id, err)
		return
	}
	w.Write(b)
}

type ipaddr net.IP

func (ip ipaddr) MarshalJSON() ([]byte, error) {
	if ip == nil {
		return []byte("null"), nil
	}
	return json.Marshal(ip.String())
}

func (ip ipaddr) String() string {
	return net.IP(ip).String()
}

type dockeripinfo struct {
	names    []string
	networks []string
	addrs    []ipaddr
}

func (entry dockeripinfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"names":    entry.names,
		"networks": entry.networks,
		"addrs":    entry.addrs,
	})
}

func (entry *dockeripinfo) addname(parts ...string) {
	var out []string
	for _, part := range parts {
		name := minimized(part)
		if name == "" {
			return
		}
		out = append(out, name)
	}
	if len(out) > 0 {
		entry.names = append(entry.names, strings.Join(out, "."))
	}
}

func (entry *dockeripinfo) addnetwork(network string) {
	entry.networks = append(entry.networks, network)
}

func (entry *dockeripinfo) addip(addr string) bool {
	ip := net.ParseIP(addr)
	ok := ip != nil
	if ok {
		entry.addrs = append(entry.addrs, ipaddr(ip))
	}
	return ok
}

func (entry dockeripinfo) add(id string) {
	if len(entry.names) == 0 || len(entry.addrs) == 0 {
		return
	}
	entry.set(true, id)
}

func (entry dockeripinfo) remove(id string) {
	entry.set(false, id)
}

func (entry dockeripinfo) set(add bool, id string) {
	if add {
		entry.dedup()
		containerInfo[id] = entry
	} else {
		delete(containerInfo, id)
	}

	for _, n := range entry.names {
		containerByName.set(add, n, id)
	}
	for _, n := range entry.networks {
		containerByNetwork.set(add, n, id)
	}
	for _, addr := range entry.addrs {
		containerByIP.set(add, addr.String(), id)
	}
}

func (entry dockeripinfo) dedup() {
	entry.names = uniq(entry.names)
	entry.networks = uniq(entry.networks)
	entry.addrs = uniqipaddrs(entry.addrs)
}

type multiset map[string]set

type set map[string]empty

func (s set) add(i string) {
	s[i] = empty{}
}

func (s set) remove(i string) {
	delete(s, i)
}

func (s set) contains(i string) bool {
	_, ok := s[i]
	return ok
}

func (s set) values() []string {
	var vs []string
	for v, _ := range s {
		vs = append(vs, v)
	}
	return vs
}

func uniqipaddrs(ips []ipaddr) []ipaddr {
	var list []ipaddr
	seen := set{}
	for _, ip := range ips {
		if !seen.contains(ip.String()) {
			list = append(list, ip)
			seen.add(ip.String())
		}
	}
	return list
}

func uniq(items []string) []string {
	var list []string
	seen := set{}
	for _, s := range items {
		if !seen.contains(s) {
			list = append(list, s)
			seen.add(s)
		}
	}
	return list
}

func sortuniq(items []string) []string {
	ret := uniq(items)
	sort.Strings(ret)
	return ret
}

type empty struct{}

func (e empty) MarshalJSON() ([]byte, error) {
	return []byte{'1'}, nil
}

func (m multiset) add(k, v string) {
	if _, ok := m[k]; !ok {
		m[k] = set{}
	}
	m[k][v] = empty{}
}

func (m multiset) remove(k, v string) {
	s, ok := m[k]
	if !ok {
		return
	}
	delete(s, v)
	if len(s) == 0 {
		delete(m, k)
	}
}

func (m multiset) set(add bool, k, v string) {
	if add {
		m.add(k, v)
	} else {
		m.remove(k, v)
	}
}

func (m multiset) get(k string) ([]string, bool) {
	var items []string
	s, found := m[k]
	if found {
		for item, _ := range s {
			items = append(items, item)
		}
	}
	return items, found
}

func (m multiset) contains(k, v string) bool {
	if s, ok := m[k]; ok {
		_, okv := s[v]
		return okv
	}
	return false
}

func (m multiset) keys() []string {
	var ks []string
	for k, _ := range m {
		ks = append(ks, k)
	}
	return ks
}

var (
	containerMutex     = &sync.Mutex{}
	containerInfo      = map[string]dockeripinfo{}
	containerByIP      = multiset{}
	containerByName    = multiset{}
	containerByNetwork = multiset{}
	kebabCase          = strings.NewReplacer("_", "-")
)

func withoutDefault(s string) string {
	return strings.TrimSuffix(s, "_default")
}

func kebabCased(s string) string {
	return kebabCase.Replace(s)
}

func minimized(name string) string {
	return kebabCased(withoutDefault(name))
}

func asJSON(val interface{}) string {
	b, err := json.MarshalIndent(val, "", "  ")
	if err == nil {
		return string(b)
	}
	return "ERR: " + err.Error()
}

func processDockerEvent(e dockerevent) {
	var add bool
	switch e.Action {
	case Connect:
		add = true
	case Disconnect:
		add = false
	default:
		log.Printf("Unexpected event action: %s", e.Action)
		return
	}
	id, ok := e.Actor.Attributes["container"]
	if !ok {
		log.Printf("network.%s event with no container attribute?", e.Action)
		return
	}
	if add {
		addContainerMappings(id)
	} else {
		clearContainerMappings(id)
	}
}

func addContainerMappings(id string) {
	containerMutex.Lock()
	defer containerMutex.Unlock()
	container, err := dockerGetContainer(id)
	if err != nil {
		log.Printf("Error reading container %s info: %s\n", id, err)
		return
	}
	var entry dockeripinfo
	autogenerated := func(n string) bool {
		return len(n) >= 8 && strings.HasPrefix(id, n)
	}
	addname := func(parts ...string) {
		if len(parts) > 0 && !autogenerated(parts[0]) {
			entry.addname(parts...)
		}
	}
	addNetworkName := func(fullname, fullnetwork string) {
		name := minimized(fullname)
		network := minimized(fullnetwork)
		addname(name)
		addname(name, network)
		entry.addnetwork(network)
	}
	addname(container.shortName())
	addname(container.Config.Hostname)
	entry.addip(container.NetworkSettings.IPAddress)
	for network, settings := range container.NetworkSettings.Networks {
		entry.addip(settings.IPAddress)
		if settings.Aliases != nil {
			for _, alias := range settings.Aliases {
				if !autogenerated(alias) {
					addNetworkName(alias, network)
				}
			}
		}
	}
	if container.isComposed() {
		comp := container.Config.Compose
		var prefixes []string
		if comp.Oneoff {
			prefixes = []string{"oneoff"}
		} else {
			prefixes = []string{"", fmt.Sprintf("%d", comp.Number)}
		}
		suffixes := []string{"", comp.Project}
		for _, pref := range prefixes {
			for _, suff := range suffixes {
				var parts []string
				for _, part := range []string{pref, comp.Service, suff} {
					if part != "" {
						parts = append(parts, part)
					}
				}
				addname(parts...)
			}
		}
	}
	entry.add(id)
}

func clearContainerMappings(id string) {
	containerMutex.Lock()
	defer containerMutex.Unlock()
	entry, ok := containerInfo[id]
	if !ok {
		return
	}
	entry.remove(id)
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
		switch res.Rcode {
		case dns.RcodeServerFailure:
			debug.Printf(" <- SERVFAIL (Rcode %v, err %v)", res.Rcode, err)
		case dns.RcodeSuccess:
		default:
			debug.Debugf(2, " <- Rcode = %v (err = %v)", res.Rcode, err)
		}
		if err == nil {
			allBogus, nonBogus := filterBogus(res.Answer)
			res.Answer = appendFiltered([]dns.RR{}, nonBogus...)
			allFiltered := len(res.Answer) == 0
			if allBogus || allFiltered {
				var reject []string
				if allBogus {
					reject = append(reject, "bogus")
				}
				if allFiltered {
					reject = append(reject, "filtered")
				}
				reason := strings.Join(reject, " and ")
				debug.Printf("A from [%s] all %s", server, reason)
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
		debug.Debugf(2, "Debug level %v from env", debug)
	} else if env != "" {
		debug = 1
		debug.Debugf(2, "Debug level %v from env != \"\"", debug)
	}
}

func setup4vs6() {
	switch os.Getenv("IPV") {
	case "4":
		debug.Printf("Only returning IPv4 (A) records by default")
		defaultAnswerAdder = addAnswerOnly4
		defaultAnswerFilter = allowVersions(4)
	case "6":
		debug.Printf("Only returning IPv6 (AAAA) records by default")
		defaultAnswerAdder = addAnswerOnly6
		defaultAnswerFilter = allowVersions(6)
	default:
		debug.Debugf(2, "Returning both IPv4 (A) and IPv6 (AAAA) records by default")
		defaultAnswerAdder = addAnswer
		defaultAnswerFilter = allowVersions(4, 6)
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
		adder := defaultAnswerAdder
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
	any := false
	for _, tld := range strings.Split(os.Getenv("DOCKER"), ",") {
		if tld == "" {
			continue
		}
		any = true
		log.Printf("Serving Docker hosts on .%s", dotted(tld))
		dns.HandleFunc(dotted(tld), docker)
		isDockerTLD[dotted(tld)] = true
	}
	if any {
		go initDocker()
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
	setup4vs6()
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
