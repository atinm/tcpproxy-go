package bpf

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -Wall" bpf ./bpf.c

type Program uint8

const (
	ProgramNone Program = iota
	ProgramSockops
	ProgramSkSkb
)

type DetachFunc func()

func LoadObjects() (*bpfObjects, error) {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}

	return &objs, nil
}

func AttachProgram(objs *bpfObjects, program Program, cgroup string) (DetachFunc, error) {
	switch program {
	case ProgramSockops:
		return attachSockopsProgram(objs.SockopsProg, cgroup)
	case ProgramSkSkb:
		return attachSkSkbProgram(objs)
	}

	return nil, fmt.Errorf("unknown program: %d", program)
}

func attachSockopsProgram(p *ebpf.Program, cgroup string) (DetachFunc, error) {
	var cgroupPath string
	var err error
	if cgroup != "" {
		cgroupPath = cgroup
	} else {
		cgroupPath, err = findCgroupPath()
		if err != nil {
			return nil, fmt.Errorf("find cgroup path: %w", err)
		}
	}

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: p,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		return nil, fmt.Errorf("attach %s to cgroup %s: %w", p.String(), cgroupPath, err)
	}

	return func() {
		if err := l.Close(); err != nil {
			log.Printf("failed to detach sockops program: %v", err)
		}
	}, nil
}

func attachSkSkbProgram(objs *bpfObjects) (DetachFunc, error) {
	/*
		if err := link.RawAttachProgram(link.RawAttachProgramOptions{
			Target:  objs.Sockmap.FD(),
			Program: objs.SkSkbStreamParserProg,
			Attach:  ebpf.AttachSkSKBStreamParser,
		}); err != nil {
			return nil, err
		}
	*/
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.Sockmap.FD(),
		Program: objs.SkSkbStreamVerdictProg,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	}); err != nil {
		return nil, err
	}

	return func() {
		if err := link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  objs.Sockmap.FD(),
			Program: objs.SkSkbStreamVerdictProg,
			Attach:  ebpf.AttachSkSKBStreamVerdict,
		}); err != nil {
			log.Printf("failed to detach sk_skb stream verdict program: %v", err)
		}
		/*
			if err := link.RawDetachProgram(link.RawDetachProgramOptions{
				Target:  objs.Sockmap.FD(),
				Program: objs.SkSkbStreamParserProg,
				Attach:  ebpf.AttachSkSKBStreamParser,
			}); err != nil {
				log.Printf("failed to detach sk_skb stream parser program: %v", err)
			}
		*/
	}, nil
}

// findCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
func findCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}

func IPv4toInt(ipv4 net.IP) uint32 {
	ipv4Bytes := ipv4.To4()
	if ipv4Bytes == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ipv4Bytes)
}

func InsertDispatchMap(client, server net.Conn, dispatchMap *ebpf.Map) error {
	key := uint32(client.LocalAddr().(*net.TCPAddr).Port)
	value := uint32(server.LocalAddr().(*net.TCPAddr).Port)
	if err := dispatchMap.Put(&key, &value); err != nil {
		log.Println("dispatchMap.Put: %w", err)
		return err
	}
	log.Println("Added mapping to dispatchMap:")
	log.Printf("\t[local_port: %d] => [local_port: %d]\n", key, value)

	key = uint32(server.LocalAddr().(*net.TCPAddr).Port)
	value = uint32(client.LocalAddr().(*net.TCPAddr).Port)
	if err := dispatchMap.Put(&key, &value); err != nil {
		log.Println("dispatchMap.Put: %w", err)
		return err
	}
	log.Println("Added mapping to dispatchMap:")
	log.Printf("\t[local_port: %d] => [local_port: %d]\n", key, value)
	return nil
}
