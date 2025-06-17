package runner

import (
	"github.com/projectdiscovery/gologger"
)

const (
	author = "ferdirianrk"
	banner = ` 
  ___ _    _____
 / _ \ |/|/ / _ \
/_//_/__,__/ .__/
          /_/    `
)

func showBanner() {
	gologger.Print().Msgf(`
%s v%s

by @%s

`, banner, version, author)
}
