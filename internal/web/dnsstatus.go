package web

import (
	"context"
	"sync"

	"github.com/max-zit/hostzit/internal/dnsprobe"
)

// secondaryState is what one secondary name server holds compared with
// this server: the SOA serial of every hosted zone. (The catalog itself is
// not served by a consuming PowerDNS, so the zones are what is compared.)
type secondaryState struct {
	IP string
	// Answer is false when the server answered no query at all.
	Answer bool
	// Synced of Total zones have the same serial; Behind lists some that do not.
	Synced, Total int
	Behind        []string
}

// localDNS is where this server's own PowerDNS answers.
var localDNS = "127.0.0.1"

// forEach runs fn for every name, at most 16 at a time.
func forEach(names []string, fn func(string)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, n := range names {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn(n)
		}(n)
	}
	wg.Wait()
}

func (s *Server) secondaryStates(ctx context.Context, h HostingSettings) []secondaryState {
	var names []string
	if zs, err := s.store.Zones(ctx, 0); err == nil {
		for _, z := range zs {
			if z.Applied {
				names = append(names, z.Name)
			}
		}
	}
	var mu sync.Mutex
	want := map[string]uint32{}
	forEach(names, func(z string) {
		if serial, ok, err := dnsprobe.SOASerial(ctx, localDNS, z); err == nil && ok {
			mu.Lock()
			want[z] = serial
			mu.Unlock()
		}
	})
	zones := make([]string, 0, len(want))
	for _, z := range names {
		if _, ok := want[z]; ok {
			zones = append(zones, z)
		}
	}
	out := make([]secondaryState, len(h.Secondaries))
	var wg sync.WaitGroup
	for i, ip := range h.Secondaries {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			st := secondaryState{IP: ip, Total: len(zones)}
			var smu sync.Mutex
			forEach(zones, func(z string) {
				got, ok, err := dnsprobe.SOASerial(ctx, ip, z)
				smu.Lock()
				defer smu.Unlock()
				if err == nil {
					st.Answer = true
				}
				if err == nil && ok && got == want[z] {
					st.Synced++
				} else if len(st.Behind) < 20 {
					st.Behind = append(st.Behind, z)
				}
			})
			if len(zones) == 0 {
				// nothing to compare: at least see whether it answers
				_, _, err := dnsprobe.SOASerial(ctx, ip, "invalid")
				st.Answer = err == nil
			}
			out[i] = st
		}(i, ip)
	}
	wg.Wait()
	return out
}
