# tcpproxy-go

You can bring up tcpproxy-go as (listen on 8000, proxy to 127.0.0.1:5000):
```
  bin/tcpproxy-go proxy -b 127.0.0.1 -l 8000 127.0.0.1:5000
```

## Curl

To test, you can use curl:
```
  curl -vvv -H "Connection: close" http://localhost:8000/
```

## IPerf3

Server:
```
  iperf3 -s -B localhost -p 5000
```

Client:
```
  iperf3 -c localhost -p 8000
```

## EBPF

The bpf/bpf.c file hardcodes ports 8000 for the proxy listener port and 5000 for the server listener port. Modify if you need different ports.

To use it, create a new cgroup `test.slice` and then add the shell you are going to run the tcpproxy in to it:

```
  mkdir -p /sys/fs/cgroup/test.slice
  echo $$ > /sys/fs/cgroup/test.slice/cgroup.procs
```

Now you can bring up tcpproxy-go in the shell that you added to the cgroup above (listen on port 8000, proxy to 127.0.0.1:5000):
```
  bin/tcpproxy-go proxy -b 127.0.0.1 -l 8000 -e 127.0.0.1:5000
```

To disable BPF, remove the `--ebpf` or `-e` flag from the above tcpproxy-go command.
