# cidr-range-overlap-checker

A small Go library that detects overlapping or adjacent IPv4 and IPv6 CIDR blocks in a list and returns the conflicting pairs.

## Usage

```go
package main

import (
	"fmt"

	cidrrangeoverlap "cidr-range-overlap-checker"
)

func main() {
	c := cidrrangeoverlap.NewChecker()
	for _, s := range []string{"10.0.0.0/24", "10.0.0.128/25", "192.168.0.0/16"} {
		if err := c.Add(s); err != nil {
			panic(err)
		}
	}

	for _, conflict := range c.Conflicts() {
		fmt.Println(conflict)
	}
}
```

## Why this exists

When you concatenate firewall rules, route tables, or allow-lists from several
sources, you end up with a flat list of CIDR blocks that may overlap or sit
side by side. Overlaps are usually a mistake: a narrower rule silently
shadows a wider one, or two teams claim the same range. Adjacent blocks are
not a correctness problem, but they are a signal that the list can be
consolidated, and they are the pairs a naive "do these two ranges intersect"
check misses.

The trade-off: this library reports conflicts, it does not resolve them. It
will not merge adjacent blocks, subtract one range from another, or pick a
winner between overlapping rules. Those operations depend on policy that the
library cannot guess. The output is a list of pairs with both the original
strings and the parsed networks, so the caller can decide what to do.

## Edge cases

`net.ParseCIDR` canonicalises host bits, so `10.0.0.5/24` is stored as
`10.0.0.0/24`. The original string is preserved in the `Conflict` for
reporting, but overlap and adjacency are computed on the canonical network.
Two inputs that differ only in host bits are therefore reported as
overlapping.

IPv4 and IPv6 blocks are never reported as conflicting with each other, even
if they happen to share a numeric prefix. The address families are disjoint;
treating them as comparable would produce false positives.

`255.255.255.255/32` has no successor address, so it cannot be adjacent to
anything on the high side. The same applies to the all-ones IPv6 address.

## API

- `NewChecker() *Checker` — create an empty checker.
- `(*Checker).Add(cidr string) error` — parse and append a CIDR block.
- `(*Checker).Len() int` — number of stored blocks.
- `(*Checker).Conflicts() []Conflict` — all overlapping or adjacent pairs.
- `Conflict` fields: `IndexA`, `IndexB`, `A`, `B`, `NetA`, `NetB`, `Overlap`, `Adjacent`.
- `(Conflict).String() string` — human-readable description.
