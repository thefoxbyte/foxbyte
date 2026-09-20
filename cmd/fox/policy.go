// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/foxbyte/foxbyte/internal/branch"
)

// policyCmd handles `fox policy …`, the Blackbox policy gate: rules checked on
// every schema change before it runs (docs/policy-errors.md). Rules live in each
// branch's database; --branch picks one (default main, which new branches copy).
func policyCmd(args []string) {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	name := optValue(args, "--branch")
	if name == "" {
		name = "main"
	}
	arg := firstPositional(args, "--branch", "--command", "--pattern", "--reason", "--hint", "--limit")
	const actor = "fox-cli"
	needArg := func() {
		if arg == "" {
			policyUsage()
		}
	}

	switch sub {
	case "list":
		rules, err := branch.PolicyRules(name)
		must(err)
		fmt.Println(branch.FormatPolicyRules(rules))
	case "check":
		needArg()
		tag, matches, err := branch.PolicyCheck(name, arg)
		must(err)
		fmt.Println(branch.FormatPolicyCheck(tag, matches))
		for _, m := range matches {
			if m.Action == "block" {
				os.Exit(1)
			}
		}
	case "block", "warn":
		needArg()
		action := sub
		must(branch.UpdatePolicyRule(name, arg, &action, nil, actor))
		fmt.Printf("%s: rule %s now %ss matching changes\n", name, arg, sub)
	case "enable", "disable":
		needArg()
		on := sub == "enable"
		must(branch.UpdatePolicyRule(name, arg, nil, &on, actor))
		fmt.Printf("%s: rule %s %sd\n", name, arg, sub)
	case "add":
		needArg()
		r := branch.PolicyRule{
			RuleID:     arg,
			CommandTag: strings.ToUpper(strings.TrimSpace(optValue(args, "--command"))),
			Action:     "warn",
			Reason:     optValue(args, "--reason"),
		}
		for _, a := range args {
			if a == "--block" {
				r.Action = "block"
			}
		}
		if p := optValue(args, "--pattern"); p != "" {
			r.Pattern = &p
		}
		if h := optValue(args, "--hint"); h != "" {
			r.Hint = &h
		}
		must(branch.AddPolicyRule(name, r, actor))
		fmt.Printf("%s: added rule %s (%s)\n", name, arg, r.Action)
	case "remove":
		needArg()
		must(branch.RemovePolicyRule(name, arg, actor))
		fmt.Printf("%s: removed rule %s\n", name, arg)
	case "evaluations":
		limit := 20
		if v := optValue(args, "--limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				limit = n
			}
		}
		evs, err := branch.PolicyEvaluations(name, limit)
		must(err)
		fmt.Println(branch.FormatPolicyEvaluations(evs))
	default:
		policyUsage()
	}
}

func policyUsage() {
	fmt.Println(`usage:
  fox policy [list] [--branch <name>]
  fox policy check "<SQL>" [--branch <name>]
  fox policy block|warn|enable|disable|remove <rule> [--branch <name>]
  fox policy add <rule> --command "ALTER TABLE" [--pattern <regex>] [--block] --reason "<why>" [--hint "<next step>"] [--branch <name>]
  fox policy evaluations [--limit N] [--branch <name>]`)
	os.Exit(2)
}
