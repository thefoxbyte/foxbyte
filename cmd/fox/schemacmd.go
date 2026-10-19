// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/controlplane"
)

// schemaCmd is `fox schema` (point 12.1): what a branch holds, read-only, and
// each object's CREATE script, as the console's object browser shows them.
//
//	fox schema [--branch b] [--all]                  every schema and what is in it
//	fox schema [--branch b] --search <text> [--kind k]
//	fox schema [--branch b] <object> [--kind k] [--ddl] [--json]
//	                                                 one object: its parts and its CREATE script
//
// <object> is a name, or schema.name; when it names several (the same table in
// two schemas, a function's overloads) each is shown. --ddl prints only the
// CREATE scripts, to save or to run elsewhere. FoxByte's own schemas (bb) are
// left out unless --all.
func schemaCmd(args []string) {
	b := optValue(args, "--branch")
	if b == "" {
		b = "main"
	}
	cat, err := controlplane.BranchCatalog(b, cliActor())
	must(err)
	kind := optValue(args, "--kind")
	all := hasFlag(args, "--all")
	var objs []controlplane.CatalogObject
	for _, o := range cat.Objects {
		if (!o.System || all) && (kind == "" || o.Kind == kind) {
			objs = append(objs, o)
		}
	}
	ps := positionals(args, "--branch", "--kind", "--search")
	if search := optValue(args, "--search"); search != "" || len(ps) == 0 {
		if search != "" {
			objs = filterObjects(objs, func(o controlplane.CatalogObject) bool {
				return strings.Contains(strings.ToLower(o.Name), strings.ToLower(search))
			})
		}
		if hasFlag(args, "--json") {
			printJSON(objs)
			return
		}
		printCatalog(os.Stdout, objs, search != "")
		return
	}
	want := strings.Join(ps, " ")
	matches := filterObjects(objs, func(o controlplane.CatalogObject) bool { return objectNamed(o, want) })
	if len(matches) == 0 {
		fmt.Fprintf(os.Stderr, "no object named %s on %s (%s schema --search %s lists what there is)\n", want, b, brand.CLI, want)
		os.Exit(1)
	}
	var details []controlplane.ObjectDetail
	for _, o := range matches {
		d, err := controlplane.BranchObject(b, cliActor(), o.Kind, o.OID)
		must(err)
		details = append(details, d)
	}
	switch {
	case hasFlag(args, "--json"):
		printJSON(details)
	case hasFlag(args, "--ddl"):
		for i, d := range details {
			if i > 0 {
				fmt.Println()
			}
			fmt.Print(d.DDL)
		}
	default:
		for i, d := range details {
			if i > 0 {
				fmt.Println()
			}
			printObject(os.Stdout, d)
		}
	}
}

func filterObjects(in []controlplane.CatalogObject, keep func(controlplane.CatalogObject) bool) []controlplane.CatalogObject {
	var out []controlplane.CatalogObject
	for _, o := range in {
		if keep(o) {
			out = append(out, o)
		}
	}
	return out
}

// objectNamed matches name or schema.name, ignoring case as unquoted SQL does;
// a schema matches its own name.
func objectNamed(o controlplane.CatalogObject, want string) bool {
	w := strings.ToLower(strings.Trim(want, `"`))
	if strings.EqualFold(o.Name, w) && o.Kind != "extension" || o.Kind == "extension" && strings.EqualFold(o.Name, w) {
		return true
	}
	return o.Schema != "" && strings.EqualFold(o.Schema+"."+o.Name, w)
}

var kindOrder = []string{"table", "view", "function", "procedure", "sequence", "type"}

// printCatalog is the tree: each schema, then what is in it by kind, then the
// extensions. With a search, a flat list.
func printCatalog(w io.Writer, objs []controlplane.CatalogObject, flat bool) {
	if flat {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "KIND\tNAME")
		for _, o := range objs {
			fmt.Fprintf(tw, "%s\t%s\n", o.Kind, displayName(o))
		}
		tw.Flush()
		if len(objs) == 0 {
			fmt.Fprintln(w, "Nothing matches.")
		}
		return
	}
	bySchema := map[string]map[string][]controlplane.CatalogObject{}
	var schemas, exts []string
	for _, o := range objs {
		switch o.Kind {
		case "schema":
			schemas = append(schemas, o.Name)
		case "extension":
			exts = append(exts, o.Name+" "+o.Sub)
		default:
			if bySchema[o.Schema] == nil {
				bySchema[o.Schema] = map[string][]controlplane.CatalogObject{}
			}
			bySchema[o.Schema][o.Kind] = append(bySchema[o.Schema][o.Kind], o)
		}
	}
	sort.Strings(schemas)
	for _, s := range schemas {
		fmt.Fprintf(w, "%s\n", s)
		empty := true
		for _, k := range kindOrder {
			list := bySchema[s][k]
			if len(list) == 0 {
				continue
			}
			empty = false
			fmt.Fprintf(w, "  %s (%d)\n", plural2(k), len(list))
			for _, o := range list {
				fmt.Fprintf(w, "    %s\n", displayName(o)[len(s)+1:])
			}
		}
		if empty {
			fmt.Fprintln(w, "  (empty)")
		}
	}
	if len(exts) > 0 {
		fmt.Fprintf(w, "extensions (%d)\n", len(exts))
		for _, e := range exts {
			fmt.Fprintf(w, "  %s\n", e)
		}
	}
}

func plural2(k string) string {
	if k == "sequence" || k == "type" || k == "table" || k == "view" || k == "function" || k == "procedure" {
		return k + "s"
	}
	return k
}

// displayName is how a person would name the object: schema.name, with a
// function's arguments, and what kind of table or type it is.
func displayName(o controlplane.CatalogObject) string {
	n := o.Name
	if o.Schema != "" && o.Kind != "extension" {
		n = o.Schema + "." + o.Name
	}
	if o.Kind == "function" || o.Kind == "procedure" {
		n += "(" + o.Args + ")"
	}
	if o.Sub != "" && o.Kind != "extension" {
		n += " [" + o.Sub + "]"
	}
	return n
}

// printObject is one object to read: what it is made of, then its CREATE script.
func printObject(w io.Writer, d controlplane.ObjectDetail) {
	fmt.Fprintf(w, "%s %s\n", d.Kind, displayName(d.CatalogObject))
	if d.Comment != "" {
		fmt.Fprintf(w, "  %s\n", d.Comment)
	}
	if len(d.Columns) > 0 {
		fmt.Fprintln(w, "\nColumns")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, c := range d.Columns {
			extra := []string{}
			if c.NotNull {
				extra = append(extra, "not null")
			}
			if c.Identity != "" {
				extra = append(extra, "identity "+c.Identity)
			}
			if c.Default != "" {
				extra = append(extra, "default "+c.Default)
			}
			if c.Generated != "" {
				extra = append(extra, "generated "+c.Generated)
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", c.Name, c.Type, strings.Join(extra, ", "))
		}
		tw.Flush()
	}
	parts := func(title string, ps []controlplane.CatalogPart) {
		if len(ps) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s\n", title)
		for _, p := range ps {
			tag := ""
			if p.System {
				tag = " (" + brand.Product + ")"
			}
			if p.Disabled {
				tag += " (disabled)"
			}
			fmt.Fprintf(w, "  %s%s: %s\n", p.Name, tag, p.Def)
		}
	}
	parts("Constraints", d.Constraints)
	parts("Indexes", d.Indexes)
	parts("Triggers", d.Triggers)
	if len(d.Facts) > 0 {
		fmt.Fprintln(w)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, f := range d.Facts {
			fmt.Fprintf(tw, "  %s\t%s\n", f[0], f[1])
		}
		tw.Flush()
	}
	if len(d.Values) > 0 {
		fmt.Fprintf(w, "\nValues: %s\n", strings.Join(d.Values, ", "))
	}
	if len(d.Members) > 0 {
		fmt.Fprintf(w, "\nInstalled (%d)\n", len(d.Members))
		for _, m := range d.Members {
			fmt.Fprintf(w, "  %s\n", m.Name)
		}
	}
	fmt.Fprintf(w, "\n-- CREATE script\n%s", d.DDL)
}
