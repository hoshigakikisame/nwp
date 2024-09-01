package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/hoshigakikisame/nwp/internal/runner"
	"github.com/projectdiscovery/gologger"
)

func main() {
	var options *runner.Options = runner.Parse()

	nwpRunner := runner.New(options)

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			gologger.Print().Msg("\nCtrl+C is pressed")
			os.Exit(0)
		}()
	}()

	nwpRunner.Run()
}
