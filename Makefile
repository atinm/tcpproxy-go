all: bpf/*.o build

bpf/*.o: bpf/*.c bpf/bpf.go
	go generate ./bpf/...

.PHONY: build
build:
	go build -o bin/tcpproxy-go ./main.go

.PHONY: clean
clean:
	rm -rf bin bpf/*.o bpf/bpf_bpf*.go
