package runner

import (
	"os"

	"github.com/projectdiscovery/gologger"
)

const version = "0.0.1"

func showVersion() {
	gologger.Print().Msgf("nwp v%s", version)
	os.Exit(2)
}
