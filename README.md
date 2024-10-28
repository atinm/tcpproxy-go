# tcpproxy-go

To use bpf, create a new cgroup `test.slice` and then add the shell you are going to run the tcpproxy in to it:

```
  mkdir -p /sys/fs/cgroup/test.slice
  echo $$ > /sys/fs/cgroup/test.slice/cgroup.procs
```

Bring up a test server if you don't have a server you want to proxy in a separate terminal/shell:

```
  ./test-server/server.py -p 5000
```

Now you can bring up tcpproxy-go in the shell that you added to the cgroup above:
```
  bin/tcpproxy-go proxy -b 127.0.0.1 -l 8000 -e 127.0.0.1:5000
```

To test, you can use curl:
```
  curl -vvv -H "Connection: close" http://localhost:8000/
```
## EBPF

The bpf/bpf.c file hardcodes ports 8000 for the proxy listener port and 5000 for the server listener port. Modify if you need different ports.

To disable BPF, remove the `--ebpf` or `-e` flag from the tcpproxy-go command.

## Inject message to the packet

To inject a `PASS\n` message to the packet for each time the proxy receives a packet, remove the comment `// #define INJECT_MSG` in the `bpf/bpf.c` file.
