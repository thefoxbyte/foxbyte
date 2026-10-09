//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"log"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// The meter: a reading on a timer, so the cost of staying warm can be asked
// about a period and not only about this instant.
//
// Modelled on StartBackupScheduler, including its weaknesses, because being the
// fourth thing of this shape in the control-plane process is better than being
// the first thing of a new shape. It runs in that process with no leader
// election, like the other three — two control planes would both sample, which
// duplicates readings rather than corrupting them, and the report subtracts
// ends rather than summing rows precisely so that it tolerates this.
//
// Scoped to branches where the feed is actually in use. Reading costs a `docker
// inspect` and a `psql`, and a reading of a branch nobody has published a table
// on answers a question nobody asked.

// Default sampling, both tunable. Five minutes is frequent enough that an hour
// of being warm has twelve readings behind it, and rare enough that a year of
// them is a few megabytes rather than a problem of its own.
const (
	defaultInterval  = 5 * time.Minute
	defaultRetention = 30 * 24 * time.Hour
)

// EnvInterval and EnvRetention tune the meter. "off" for the interval stops it
// entirely, for an install that would rather not keep the series at all.
const (
	EnvInterval  = "REALTIME_METER_INTERVAL"
	EnvRetention = "REALTIME_METER_RETAIN"
)

// HubsFor is how the meter finds the live fan-out for a branch, if there is
// one. Injected because the hubs live in the control plane: the package that
// decodes WAL should not also own the registry of who is listening, and a test
// needs to supply its own.
type HubsFor func(branch string) *Hub

// StartMeter samples every branch using the feed, on a timer, and trims the
// series as it goes.
//
// Returns without starting anything when the interval is off, saying so once —
// an operator who turned it off should see that confirmed in the log rather
// than wonder whether it failed.
func StartMeter(store *auth.Store, hubs HubsFor) {
	iv := meterInterval()
	if iv == 0 {
		log.Printf("realtime meter: off (%s)", brand.EnvPrefix+EnvInterval)
		return
	}
	if store == nil {
		log.Printf("realtime meter: no store, so nothing is recorded")
		return
	}
	retain := meterRetention()
	log.Printf("realtime meter: a reading every %s, kept for %s", iv, retain)
	go func() {
		// Let the stack settle, as the backup scheduler does: sampling during
		// start-up measures start-up.
		time.Sleep(time.Minute)
		for {
			MeterOnce(store, hubs, retain)
			time.Sleep(iv)
		}
	}()
}

// MeterOnce takes one round of readings. Exported so a test can run a round
// without waiting for a timer, and so `realtime activity` can take a reading
// itself when the series is empty.
func MeterOnce(store *auth.Store, hubs HubsFor, retain time.Duration) {
	if !branch.RealtimeOn() {
		return // nothing can be streaming, so there is nothing to meter
	}
	for _, name := range meterSubjects() {
		if err := meterBranch(store, hubs, name); err != nil {
			// Logged and skipped. A branch that cannot be read — suspended
			// mid-round, deleted, a docker daemon not answering — must not stop
			// the others being read.
			log.Printf("realtime meter: %s: %v", name, err)
		}
	}
	if retain > 0 {
		if n, err := store.TrimActivity(time.Now().Add(-retain).Unix()); err != nil {
			log.Printf("realtime meter: trimming: %v", err)
		} else if n > 0 {
			log.Printf("realtime meter: dropped %d reading(s) older than %s", n, retain)
		}
	}
}

// meterSubjects is the branches worth reading: those with a table published, or
// a feed slot, or both.
//
// Not every branch. The cost this measures is the cost of the feed, and a
// branch nobody has enabled a table on is paying none of it — reading it would
// add a docker inspect and a psql per branch per interval for an answer that is
// always the same.
func meterSubjects() []string {
	infos, err := branch.Branches()
	if err != nil {
		log.Printf("realtime meter: listing branches: %v", err)
		return nil
	}
	var out []string
	for _, b := range infos {
		if b.State != "running" {
			// A suspended branch is the cheap state and has nothing to report.
			// It is also the state in which neither query below would work.
			continue
		}
		used := false
		if tables, err := branch.PublishedTables(b.Name); err == nil && len(tables) > 0 {
			used = true
		}
		if !used {
			if slots, err := branch.RealtimeSlots(b.Name); err == nil && len(slots) > 0 {
				used = true
			}
		}
		if used {
			out = append(out, b.Name)
		}
	}
	return out
}

func meterBranch(store *auth.Store, hubs HubsFor, name string) error {
	c, err := branch.ReadCounters(name)
	if err != nil {
		return err
	}
	a := auth.ActivitySample{
		Branch:       name,
		At:           time.Now().Unix(),
		Transactions: c.Transactions,
		RowsReturned: c.RowsReturned,
		StatsReset:   c.StatsReset,
	}
	if warm, err := branch.WarmSince(name); err == nil && !warm.IsZero() {
		a.WarmSince = warm.Unix()
	}
	if hubs != nil {
		if h := hubs(name); h != nil {
			a.Subscribers, a.Events, _ = h.Stats()
		}
	}
	if lags, err := branch.ReadSlotLag(name); err == nil {
		for _, l := range lags {
			a.WALHeld += l.HeldBytes
		}
	}
	return store.RecordActivity(a)
}

func meterInterval() time.Duration {
	v := strings.ToLower(strings.TrimSpace(brand.Getenv(EnvInterval)))
	switch v {
	case "":
		return defaultInterval
	case "off", "0", "false":
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("realtime meter: %s=%q is not a duration; using %s", brand.EnvPrefix+EnvInterval, v, defaultInterval)
		return defaultInterval
	}
	// A floor, because the reading costs a docker inspect and two queries per
	// branch: somebody setting this to a second would be measuring the meter.
	if d < 30*time.Second {
		log.Printf("realtime meter: %s=%s is below the 30s floor; using 30s", brand.EnvPrefix+EnvInterval, d)
		return 30 * time.Second
	}
	return d
}

func meterRetention() time.Duration {
	v := strings.ToLower(strings.TrimSpace(brand.Getenv(EnvRetention)))
	if v == "" {
		return defaultRetention
	}
	if v == "off" || v == "0" {
		return 0 // keep everything, and say so by returning zero
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		log.Printf("realtime meter: %s=%q is not a duration; keeping %s", brand.EnvPrefix+EnvRetention, v, defaultRetention)
		return defaultRetention
	}
	return d
}
