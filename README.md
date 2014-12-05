# localdns

A simple, local, wildcarding DNS server

# Features

- map wildcarded domains...
    - ...to local IP
    - ...to loopback
    - ...to a specific target
- recursively resolve domains...
    - ...via servers specified for that domain
    - ...via a specified `resolv.conf`-formatted file
        - so you can use this as your primary local DNS resolver

# Compile

## Local `go`

```sh
go get github.com/miekg/dns
go build
```

## Docker

```sh
install=$HOME/bin
case "$(uname)" in
  Darwin) GOOS=darwin ;;
  *) GOOS=linux ;;
esac
docker run --rm \
  -v $(pwd):/localdns \
  -v ${install}:/out \
  -w /localdns \
  -e GOOS=$GOOS \
  -e GOARCH=amd64 \
  -e GOBIN=/out \
  golang:1.3.3-cross \
  go get -v ./...
```

# Configuration

All configuration is via environment variables.

- `CNAMES=src:target,src2:target2,...`
    - `*.src` will return a CNAME to `target`
    - `localdns` will also look up `target`s A record(s)
    - no default

- `SELF=name,name2,...`
    - `*.name` will point to local, non-loopback IP address(es)
    - no default

- `LOOP=name,name2,...`
    - `*.name` will point to 127.0.0.1
    - no default

- `SERVERS=name/name2/server,server2,...`
    - use `server` for upstream resolving
    - if `name/` is present, only use `server` for names ending in `name`
    - otherwise `server` is used unconditionally
    - if any `server` matches (including unconditionally), `RESOLV` will not be used
    - no default (will fall through to `RESOLV`)

- `RESOLV=filename`
    - use `filename` as the `resolv.conf`-formatted source for upstream servers
    - default `/etc/resolv.conf` won't work if using as primary DNS server

- `ADDR=ip:port`
    - listen on `port`, binding `ip`
    - no default

- `PORT=port`
    - listen on `port`, not bound to a specific interface
    - default `9753`

## Examples

### Server command

```sh
sudo env \
  CNAMES=nginx.nginx.dev.docker:example.dev \
  SELF=me \
  LOOP=dev \
  SERVERS=docker/127.0.0.1:5553,int.vpc/10.10.1.51,int.vpc/10.10.1.50 \
  RESOLV=/etc/resolv.conf.upstream \
  PORT=53 \
  localdns
```

### Example results

```sh
$ dig @localhost +noall +answer my.machine.dev
my.machine.dev.  60  IN  A  127.0.0.1

$ dig @localhost +noall +answer an.arbitrarily.long.name.me
an.arbitrarily.long.name.me.  60  IN  A  192.168.30.40
an.arbitrarily.long.name.me.  60  IN  A  172.17.42.1

$ dig @localhost +noall +answer bhaskell.example.dev
bhaskell.example.dev.    60  IN  CNAME  nginx.nginx.dev.docker.
nginx.nginx.dev.docker.  22  IN  A      172.17.0.26

$ dig @localhost +noall +answer google.com
google.com.  193  IN  A  74.125.228.7
google.com.  193  IN  A  74.125.228.2
google.com.  193  IN  A  74.125.228.8
...
```

## Permissions

`sudo` is only needed when listening on a "privileged" port (`<= 1024`), and
can be replaced by capabilities on Linux:

```sh
setcap cap_net_bind_service=+ep `which localdns`
```

# Why?

I've been a huge fan of [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html)
for a long time, but I needed an extra feature: arbitrary CNAME mapping.

From the [dnsmasq man page](http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html),
under the `--cname=<cname>,<target>` option:

```
Return a CNAME record which indicates that <cname> is really <target>.  There
are significant limitations on the target; it must be a DNS name which is known
to dnsmasq from /etc/hosts (or additional hosts files), from DHCP, from
--interface-name or from another --cname. If the target does not satisfy this
criteria, the whole cname is ignored.
```
