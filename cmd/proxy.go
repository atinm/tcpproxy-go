package cmd

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"

	"tcpproxy-go/bpf"

	"github.com/spf13/cobra"
)

func newAbort() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		<-ch
		close(ch)
	}()
	return ch
}

func proxyUsage(cmd *cobra.Command) error {
	if cmd.Use == "proxy" {
		fmt.Print(`
Usage:
  proxy [flags] <remote server address:port>

Flags:
  -b, --bind string   bind address [default: 127.0.0.1]
  -d, --debug         enable debug mode [default: false]
  -e, --ebpf          enable BPF programs [default: false]
  -l, --local string  local address [default: 8001]
`)
		return nil
	} else {
		return cmd.Usage()
	}
}

func ProxyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "proxy",
		Run: runProxy,
	}
	cmd.Flags().StringP("bind", "b", "127.0.0.1", "bind address")
	cmd.Flags().StringP("local", "l", "8001", "local address")
	cmd.Flags().BoolP("ebpf", "e", false, "enable BPF programs")
	cmd.Flags().BoolP("debug", "d", false, "enable debug mode")
	cmd.SetUsageFunc(proxyUsage)
	return cmd
}

func runProxy(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()

	enableBPF, err := cmd.Flags().GetBool("ebpf")
	if err != nil {
		enableBPF = false
	}

	if enableBPF {
		objs, err := bpf.LoadObjects()
		if err != nil {
			log.Fatalln("Failed to load objects:", err)
		}
		defer objs.Close()

		{
			cancel, err := bpf.AttachProgram(objs, bpf.ProgramSockops)
			if err != nil {
				log.Fatalf("Failed to attach sockops program: %v\n", err)
			}
			defer cancel()
		}
		{
			cancel, err := bpf.AttachProgram(objs, bpf.ProgramSkSkb)
			if err != nil {
				log.Fatalf("Failed to attach sk_skb program: %v\n", err)
			}
			defer cancel()
		}

		log.Println("BPF programs are attached")
	}

	bind, err := cmd.Flags().GetString("bind")
	if err != nil {
		bind = "127.0.0.1"
	}
	localPort, err := cmd.Flags().GetString("local")
	if err != nil {
		log.Fatalf("Failed to get local address: %v", err)
	}
	bindAddr := net.JoinHostPort(bind, fmt.Sprint(localPort))
	remoteAddr := ""
	if len(cmd.Flags().Args()) != 1 {
		log.Fatalf("Expected Remote Server Address argument, got %d", len(cmd.Flags().Args()))
	} else {
		remoteAddr = cmd.Flags().Args()[0]
		if _, _, err := net.SplitHostPort(remoteAddr); err != nil {
			log.Fatalf("Failed to parse remote address (%s): %v", remoteAddr, err)
		}
	}

	conn, err := net.Listen("tcp", bindAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer conn.Close()

	log.Printf("Listening on %s", conn.Addr())

	go func() {
		for {
			lconn, err := conn.Accept()
			if err != nil {
				log.Fatalln("Failed to accept connection:", err)
			}

			go func(conn net.Conn) {
				defer conn.Close()

				rconn, err := net.Dial("tcp", remoteAddr)
				if err != nil {
					log.Printf("Failed to connect to remote: %v\n", err)
					return
				}
				defer rconn.Close()

				log.Printf("Connected to remote server [%s]->[%s]", rconn.LocalAddr(), rconn.RemoteAddr())

				wg := &sync.WaitGroup{}
				wg.Add(2)

				go func(abort <-chan struct{}) {
					log.Println("Starting to forward traffic from client to server")

					defer wg.Done()

					for {
						select {
						case <-abort:
							return
						default:
						}
						buf := make([]byte, 1024)
						n, err := conn.Read(buf)
						if err != nil {
							log.Println("Connection closed by client")
							rconn.Close()
							return
						}
						log.Printf("Received %d bytes from client\n%s\n", n, hex.Dump(buf[:n]))

						m, err := rconn.Write(buf[:n])
						if err != nil {
							log.Println("Failed to write to server:", err)
							return
						}
						log.Printf("Sent %d bytes to server\n%s\n", m, hex.Dump(buf[:m]))
					}
				}(newAbort())

				go func(abort <-chan struct{}) {
					log.Println("Starting to forward traffic from server to client")

					defer wg.Done()
					for {
						select {
						case <-abort:
							return
						default:
						}

						buf := make([]byte, 1024)
						n, err := rconn.Read(buf)
						if err != nil {
							log.Println("Connection closed by server")
							conn.Close()
							return
						}
						log.Printf("Received %d bytes from server\n%s\n\n", n, hex.Dump(buf[:n]))

						m, err := conn.Write(buf[:n])
						if err != nil {
							log.Println("Failed to write to client:", err)
							return
						}
						log.Printf("Sent %d bytes to client\n%s\n", m, hex.Dump(buf[:m]))
					}
				}(newAbort())

				wg.Wait()

				log.Println("Connection closed")
			}(lconn)
		}
	}()

	<-ctx.Done()
}
