package linklocal

import "testing"

func TestFromMAC(t *testing.T) {
	got, err := FromMAC("52:55:55:b1:1f:d9")
	if err != nil {
		t.Fatal(err)
	}
	if got != "fe80::5055:55ff:feb1:1fd9" {
		t.Fatalf("derived link-local address %q", got)
	}
	if _, err := FromMAC("not-a-mac"); err == nil {
		t.Fatal("invalid MAC was accepted")
	}
}
