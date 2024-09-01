package runner

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hoshigakikisame/nwp/internal/utils"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
)

type runner struct {
	options *Options
}

func New(options *Options) *runner {
	return &runner{options: options}
}

func getFingerPrint(domain string) (int, error) {

	dnsClient := dns.Client{
		Timeout: time.Second,
	}
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.SetQuestion(domain+".", dns.TypeA)
	res, _, err := dnsClient.Exchange(&msg, "8.8.8.8:53")
	if err != nil {
		return -1, err
	}

	return len(res.Answer), nil
}

func worker(subChan chan string, wg *sync.WaitGroup, baseFP int, commonFP int, resultChan chan<- string) {
	defer wg.Done()
	for sub := range subChan {
		subFP, err := getFingerPrint(sub)
		if err != nil {
			gologger.Warning().Msgf("Unable to get %s fingerprint, continuing", sub)
			continue
		}
		if subFP != baseFP && subFP != commonFP {
			resultChan <- sub
		}
	}
}

func (r *runner) Run() {

	subGroup := make(map[string][]string)

	// Sort wildcards by level
	sort.SliceStable(o.Wildcards, func(i, j int) bool {
		return strings.Count(o.Wildcards[i], ".") > strings.Count(o.Wildcards[j], ".")
	})

	// Group subdomains under their corresponding wildcard
	gologger.Info().Msgf("Grouping subdomains")
	for _, w := range o.Wildcards {
		suffix := "." + w

		for i := 0; i < len(o.Subdomains); {
			s := o.Subdomains[i]

			if !utils.IsValidDomain(s) {
				o.Subdomains = append(o.Subdomains[:i], o.Subdomains[i+1:]...)
				i++
				continue
			}

			if strings.HasSuffix(s, suffix) {
				subGroup[w] = append(subGroup[w], s)
				o.Subdomains = append(o.Subdomains[:i], o.Subdomains[i+1:]...)
			} else {
				i++
			}
		}
	}

	validSubs := make(chan string, len(o.Subdomains))

	for wildcard, subs := range subGroup {

		gologger.Info().Msgf("Eliminating invalid %s instances..", wildcard)

		jobs := make(chan string)
		var wg sync.WaitGroup

		baseFP, err := getFingerPrint(wildcard)
		if err != nil {
			gologger.Warning().Msgf("Unable to get %s fingerprint, continuing", wildcard)
			continue
		}

		commonFP, err := getFingerPrint(fmt.Sprintf("%d.%s", rand.Int(), wildcard))
		if err != nil {
			gologger.Warning().Msgf("Unable to get %s fingerprint, continuing", wildcard)
			continue
		}

		for i := 0; i <= r.options.Concurrency; i++ {
			wg.Add(1)
			go worker(jobs, &wg, baseFP, commonFP, validSubs)
		}

		for _, sub := range subs {
			jobs <- sub
		}

		close(jobs)
		wg.Wait()
	}

	close(validSubs)
	for sub := range validSubs {
		fmt.Println(sub)
	}

	for _, sub := range o.Subdomains {
		fmt.Println(sub)
	}
}
