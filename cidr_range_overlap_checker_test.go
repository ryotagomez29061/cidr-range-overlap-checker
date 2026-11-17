package cidrrangeoverlap

import (
	"net"
	"testing"
)

func mustAdd(t *testing.T, c *Checker, cidr string) {
	t.Helper()
	if err := c.Add(cidr); err != nil {
		t.Fatalf("Add(%q) returned unexpected error: %v", cidr, err)
	}
}

func TestNoConflicts(t *testing.T) {
	c := NewChecker()
	mustAdd(t, c, "10.0.0.0/24")
	mustAdd(t, c, "10.0.2.0/24")
	mustAdd(t, c, "192.168.1.0/24")

	got := c.Conflicts()
	if len(got) != 0 {
		t.Fatalf("expected no conflicts, got %d: %v", len(got), got)
	}
}

func TestOverlap(t *testing.T) {
	c := NewChecker()
	mustAdd(t, c, "10.0.0.0/24")
	mustAdd(t, c, "10.0.0.128/25")

	got := c.Conflicts()
	if len(got) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(got), got)
	}
	if !got[0].Overlap {
		t.Errorf("expected Overlap=true, got %+v", got[0])
	}
	if got[0].Adjacent {
		t.Errorf("expected Adjacent=false, got %+v", got[0])
	}
	if got[0].IndexA != 0 || got[0].IndexB != 1 {
		t.Errorf("unexpected indices: %d, %d", got[0].IndexA, got[0].IndexB)
	}
	if got[0].A != "10.0.0.0/24" || got[0].B != "10.0.0.128/25" {
		t.Errorf("unexpected raw strings: %q, %q", got[0].A, got[0].B)
	}
}

func TestAdjacent(t *testing.T) {
	c := NewChecker()
	mustAdd(t, c, "10.0.0.0/25")
	mustAdd(t, c, "10.0.0.128/25")

	got := c.Conflicts()
	if len(got) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(got), got)
	}
	if got[0].Overlap {
		t.Errorf("expected Overlap=false, got %+v", got[0])
	}
	if !got[0].Adjacent {
		t.Errorf("expected Adjacent=true, got %+v", got[0])
	}
}

func TestAdjacentReversed(t *testing.T) {
	c := NewChecker()
	mustAdd(t, c, "10.0.0.128/25")
	mustAdd(t, c, "10.0.0.0/25")

	got := c.Conflicts()
	if len(got) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(got), got)
	}
	if !got[0].Adjacent {
		t.Errorf("expected Adjacent=true, got %+v", got[0])
	}
}

func TestIPv6Overlap(t *testing.T) {
	c := NewChecker()
	mustAdd(t, c, "2001:db8::/32")
	mustAdd(t, c, "2001:db8:1::/48")

	got := c.Conflicts()
	if len(got) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(got), got)
	}
	if !got[0].Overlap {
		t.Errorf("expected Overlap=true, got %+v", got[0])
	}
}

func TestIPv6Adjacent(t *testing.T) {
	c := NewChecker()
	mustAdd(t, c, "2001:db8::/33")
	mustAdd(t, c, "2001:db8:8000::/33")

	got := c.Conflicts()
	if len(got) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(got), got)
	}
	if !got[0].Adjacent {
		t.Errorf("expected Adjacent=true, got %+v", got[0])
	}
	if got[0].Overlap {
		t.Errorf("expected Overlap=false, got %+v", got[0])
	}
}

func TestMixedFamiliesAreNotConflicts(t *testing.T) {
	c := NewChecker()
	mustAdd(t, c, "10.0.0.0/24")
	mustAdd(t, c, "2001:db8::/32")

	got := c.Conflicts()
	if len(got) != 0 {
		t.Fatalf("expected mixed families to be ignored, got %d: %v", len(got), got)
	}
}

func TestInvalidCIDR(t *testing.T) {
	c := NewChecker()
	if err := c.Add("not-a-cidr"); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if err := c.Add("10.0.0.0/33"); err == nil {
		t.Fatal("expected error for out-of-range prefix")
	}
	if c.Len() != 0 {
		t.Fatalf("expected Len()==0 after failed adds, got %d", c.Len())
	}
}

func TestHostBitsMasked(t *testing.T) {
	// net.ParseCIDR canonicalises host bits, so 10.0.0.5/24 becomes
	// 10.0.0.0/24. Two inputs that differ only in host bits should still
	// be reported as overlapping.
	c := NewChecker()
	mustAdd(t, c, "10.0.0.5/24")
	mustAdd(t, c, "10.0.0.7/24")

	got := c.Conflicts()
	if len(got) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(got), got)
	}
	if !got[0].Overlap {
		t.Errorf("expected Overlap=true, got %+v", got[0])
	}
	if got[0].A != "10.0.0.5/24" || got[0].B != "10.0.0.7/24" {
		t.Errorf("raw strings should be preserved, got %q, %q", got[0].A, got[0].B)
	}
}

func TestMultipleConflictsOrdered(t *testing.T) {
	c := NewChecker()
	mustAdd(t, c, "10.0.0.0/24")
	mustAdd(t, c, "10.0.0.0/25")
	mustAdd(t, c, "10.0.0.128/25")

	got := c.Conflicts()
	if len(got) != 3 {
		t.Fatalf("expected 3 conflicts, got %d: %v", len(got), got)
	}
	// Pairs are ordered by first index, then second index.
	wantPairs := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for i, want := range wantPairs {
		if got[i].IndexA != want[0] || got[i].IndexB != want[1] {
			t.Errorf("conflict %d: got indices (%d,%d), want (%d,%d)",
				i, got[i].IndexA, got[i].IndexB, want[0], want[1])
		}
	}
}

func TestFullRangeAdjacencyAtBoundary(t *testing.T) {
	// 0.0.0.0/1 and 128.0.0.0/1 together cover the whole IPv4 space and
	// are adjacent: the last address of the first is 127.255.255.255 and
	// the first of the second is 128.0.0.0.
	c := NewChecker()
	mustAdd(t, c, "0.0.0.0/1")
	mustAdd(t, c, "128.0.0.0/1")

	got := c.Conflicts()
	if len(got) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(got), got)
	}
	if !got[0].Adjacent || got[0].Overlap {
		t.Errorf("expected adjacent-only conflict, got %+v", got[0])
	}
}

func TestLastAddressHasNoSuccessor(t *testing.T) {
	// 255.255.255.255/32 has no next address, so it cannot be adjacent to
	// anything on the high side.
	c := NewChecker()
	mustAdd(t, c, "255.255.255.255/32")
	mustAdd(t, c, "0.0.0.0/32")

	got := c.Conflicts()
	if len(got) != 0 {
		t.Fatalf("expected no conflicts, got %d: %v", len(got), got)
	}
}

func TestConflictString(t *testing.T) {
	c := NewChecker()
	mustAdd(t, c, "10.0.0.0/24")
	mustAdd(t, c, "10.0.0.0/25")

	got := c.Conflicts()
	if len(got) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(got))
	}
	want := `overlap: "10.0.0.0/24" (index 0) and "10.0.0.0/25" (index 1)`
	if s := got[0].String(); s != want {
		t.Errorf("String() = %q, want %q", s, want)
	}
}

func TestNetFieldsAreParsed(t *testing.T) {
	c := NewChecker()
	mustAdd(t, c, "192.168.0.0/16")
	mustAdd(t, c, "192.168.1.0/24")

	got := c.Conflicts()
	if len(got) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(got))
	}
	if got[0].NetA == nil || got[0].NetB == nil {
		t.Fatal("expected parsed networks to be populated")
	}
	_, wantNet, err := net.ParseCIDR("192.168.0.0/16")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	if got[0].NetA.String() != wantNet.String() {
		t.Errorf("NetA = %v, want %v", got[0].NetA, wantNet)
	}
}
