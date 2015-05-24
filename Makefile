permissions:	localdns
	sudo setcap cap_net_bind_service=+ep localdns

localdns:	deps localdns.go
	go build

deps:
	go list -f '{{join .Deps "\n"}}' ./... | awk -F/ 'NF>2' | xargs go get
