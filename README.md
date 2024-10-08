## What it is?

`tcp-options`is an eBPF programm which extract TCP header options from every SYN packet on the given interface and pass it to userspace.

## Prerequisites
`sudo apt install clang libbpf-dev`

`sudo snap install go`

`git clone -b dev`

## Build

```
cd bpf
clang o-O3 -c -target bpf tcp_options.c -o tcp_options.bpf.o
cd -
```
```
cd user
go mod init tcp-options
go mod tidy
go get github.com/cilium/ebpf/cmd/bpf2go
go generate
go build
```

## Run

`./tcp-options`
