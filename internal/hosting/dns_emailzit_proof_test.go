package hosting

import "testing"

func TestAllowedForEmailZitProof(t *testing.T) {
	if err := AllowedForEmailZit(Record{Name: "_emailzit", Type: "TXT", Content: "emailzit-verify=abc"}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Record{{Name: "_emailzit", Type: "A", Content: "192.0.2.1"}, {Name: "_emailzit", Type: "CNAME", Content: "x.example."}, {Name: "_emailzit.www", Type: "TXT", Content: "x"}} {
		if AllowedForEmailZit(r) == nil {
			t.Errorf("%+v allowed", r)
		}
	}
}
