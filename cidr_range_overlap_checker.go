// Package cidrrangeoverlap detects overlapping or adjacent IPv4 and IPv6 CIDR
// blocks in a list.
//
// The zero value of Checker is not useful: use NewChecker. A Checker holds a
// slice of parsed networks in the order they were added, so conflict reports
// are stable and reproducible.
package cidrrangeoverlap

import (
	"fmt"
	"net"
)

// Conflict describes a pair of CIDR blocks that overlap or are adjacent.
//
// A and B are the original strings as supplied by the caller. IndexA and
// IndexB are their positions in the input slice, with IndexA < IndexB. The
// Networks field holds the parsed *net.IPNet values so callers can inspect
// the actual ranges without re-parsing.
//
// Overlap is true when the two networks share at least one address. Adjacent
// is true when the two networks do not overlap but the end of one is exactly
// one address away from the start of the other (in either order). Both may be
// false if the caller constructs a Conflict by hand; the Checker never does.
type Conflict struct {
	IndexA int
	IndexB int
	A      string
	B      string

	NetA *net.IPNet
	NetB *net.IPNet

	Overlap  bool
	Adjacent bool
}

// String returns a human-readable description of the conflict.
func (c Conflict) String() string {
	kind := "overlap"
	if c.Adjacent && !c.Overlap {
		kind = "adjacent"
	}
	return fmt.Sprintf("%s: %q (index %d) and %q (index %d)", kind, c.A, c.IndexA, c.B, c.IndexB)
}

// Checker accumulates CIDR blocks and reports conflicts between them.
//
// It is not safe for concurrent use; the caller is expected to serialise
// Add and Conflicts calls if needed.
type Checker struct {
	entries []entry
}

type entry struct {
	raw string
	ipn *net.IPNet
}

// NewChecker returns an empty Checker.
func NewChecker() *Checker {
	return &Checker{}
}

// Add parses a CIDR block and appends it to the checker. It returns an error
// if the string is not a valid CIDR notation. The network is canonicalised
// with net.ParseCIDR, so host bits in the input are masked off; the original
// string is preserved for reporting.
func (c *Checker) Add(cidr string) error {
	_, ipn, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	c.entries = append(c.entries, entry{raw: cidr, ipn: ipn})
	return nil
}

// Len returns the number of CIDR blocks currently stored.
func (c *Checker) Len() int {
	return len(c.entries)
}

// Conflicts returns every pair of stored CIDR blocks that overlap or are
// adjacent. Pairs are reported once, with the lower index first, and are
// ordered by the index of the first member of the pair and then by the index
// of the second.
//
// A pair is considered a conflict if the two networks share at least one
// address (overlap) or if the end of one is exactly one address away from
// the start of the other (adjacency). Mixed IPv4 and IPv6 pairs are never
// conflicts because the address families are disjoint.
func (c *Checker) Conflicts() []Conflict {
	var out []Conflict
	for i := 0; i < len(c.entries); i++ {
		for j := i + 1; j < len(c.entries); j++ {
			a := c.entries[i]
			b := c.entries[j]
			overlap, adjacent := compare(a.ipn, b.ipn)
			if overlap || adjacent {
				out = append(out, Conflict{
					IndexA:   i,
					IndexB:   j,
					A:        a.raw,
					B:        b.raw,
					NetA:     a.ipn,
					NetB:     b.ipn,
					Overlap:  overlap,
					Adjacent: adjacent,
				})
			}
		}
	}
	return out
}

// compare reports whether two networks overlap and whether they are adjacent.
//
// Adjacency is defined as: the two networks do not overlap, but the end of one
// is exactly one address away from the start of the other. This is the
// definition that matters for routing table consolidation: two adjacent
// blocks can be merged into one larger block without changing the covered
// address set. Overlap is checked first so that a pair is never reported as
// both.
func compare(a, b *net.IPNet) (overlap bool, adjacent bool) {
	if !sameFamily(a, b) {
		return false, false
	}
	if overlaps(a, b) {
		return true, false
	}
	if adjacentTo(a, b) || adjacentTo(b, a) {
		return false, true
	}
	return false, false
}

// sameFamily reports whether both networks use the same address family. An
// IPv4 address and an IPv4-mapped IPv6 address are considered the same family
// because net.IPNet normalises them to 4-byte form when the mask is 4 bytes
// wide.
func sameFamily(a, b *net.IPNet) bool {
	return len(a.IP) == len(b.IP)
}

// overlaps reports whether two networks share at least one address. It assumes
// a and b are the same address family.
func overlaps(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// adjacentTo reports whether the network x ends exactly one address before
// the network y begins. It assumes x and y are the same address family and do
// not overlap.
func adjacentTo(x, y *net.IPNet) bool {
	last := lastIP(x)
	next := nextIP(last)
	if next == nil {
		return false
	}
	return y.Contains(next) && next.Equal(y.IP)
}

// lastIP returns the last address in the network. It assumes n is a valid
// network produced by net.ParseCIDR.
func lastIP(n *net.IPNet) net.IP {
	ip := n.IP
	mask := n.Mask
	out := make(net.IP, len(ip))
	for i := range ip {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}

// nextIP returns the address immediately after ip, or nil if ip is the last
// address in its family (255.255.255.255 or the all-ones IPv6 address). The
// returned address has the same length as ip.
func nextIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			return out
		}
	}
	return nil
}
