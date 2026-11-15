// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// auditPrivacyCmd is the security log's privacy upkeep:
//
//	fox audit prune               remove events older than FOX_SECURITY_LOG_RETENTION now
//	fox audit pseudonym <email>   the token a deleted account's email became
//
// Pruning also runs with every checkpoint; this is for running it by hand, for
// example right after setting a retention. The pseudonym is for an
// investigation that already knows an email and wants that person's events
// after their account is gone. It is computed from the install's key, so it
// says nothing to anyone without it.
func auditPrivacyCmd(s *auth.Store, sub string, args []string) {
	switch sub {
	case "prune":
		ret, err := branch.SecurityLogRetention()
		must(err)
		if ret == 0 {
			fmt.Printf("%s is not set, so the security log keeps everything; set it (for example 400d) to the period your policy requires\n",
				auth.SecurityLogRetentionEnv)
			return
		}
		res, err := branch.PruneSecurityLog(s, cliActor())
		must(err)
		if res.Removed == 0 {
			fmt.Printf("security log: nothing older than %s that is already anchored (anchor first: %s audit checkpoint)\n",
				ret, brand.CLI)
			return
		}
		fmt.Printf("security log: removed %d events, up to event %d; the log now starts from its hash, recorded in event %d\n",
			res.Removed, res.UpTo, res.EventID)
	case "pseudonym":
		if len(args) < 1 {
			fmt.Printf("usage: %s audit pseudonym <email>\n", brand.CLI)
			os.Exit(2)
		}
		p, err := s.Pseudonym(args[0])
		must(err)
		// Turning a person into their token is how their events are found
		// again, so who did it is recorded — by the token, not the email.
		s.Audit(auth.EvSecurityLogPseudonymLookup, cliActor(), p, "", "")
		fmt.Println(p)
	}
}
