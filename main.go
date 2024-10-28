package main

import (
	"context"
	"os"
	"os/signal"

	"tcpproxy-go/cmd"

	"github.com/spf13/cobra"
)

func main() {
	c := &cobra.Command{
		Use: "tcpproxy-go",
	}

	c.AddCommand(
		cmd.ProxyCommand(),
	)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := c.ExecuteContext(ctx); err != nil {
		panic(err)
	}
}
