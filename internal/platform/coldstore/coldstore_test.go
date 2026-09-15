package coldstore

import (
	"bytes"
	"testing"
	"time"

	"github.com/parquet-go/parquet-go"
)

func TestEncodeRoundTrip(t *testing.T) {
	s := NewSchema("t", map[string]Kind{"id": Int, "ok": Bool, "amount": Double, "name": String, "at": String, "detail": String})
	at := time.Date(2026, 1, 2, 3, 4, 5, 600, time.UTC)
	data, err := s.Encode([]map[string]any{
		{"id": int32(1), "ok": true, "amount": 1.5, "name": "a", "at": at, "detail": map[string]any{"k": "v"}},
		{"id": nil, "name": nil},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := parquet.NewReader(bytes.NewReader(data))
	rows := make([]parquet.Row, 2)
	n, _ := r.ReadRows(rows)
	if n != 2 {
		t.Fatalf("read %d rows", n)
	}
	cols := s.Columns()
	got := map[string]string{}
	for _, v := range rows[0] {
		got[cols[v.Column()]] = v.String()
	}
	if got["id"] != "1" || got["ok"] != "true" || got["amount"] != "1.5" || got["name"] != "a" {
		t.Fatalf("row 0: %v", got)
	}
	if got["at"] != "2026-01-02T03:04:05.0000006Z" {
		t.Fatalf("time: %q", got["at"])
	}
	if got["detail"] != `{"k":"v"}` {
		t.Fatalf("detail: %q", got["detail"])
	}
	for _, v := range rows[1] {
		if !v.IsNull() {
			t.Fatalf("row 1 should be all null, got %s=%v", cols[v.Column()], v)
		}
	}
}

func TestKey(t *testing.T) {
	k := Key("archive", "auth_audit_log", time.Date(2026, 9, 15, 23, 0, 0, 0, time.FixedZone("WIB", 7*3600)), "run1")
	if k != "archive/auth_audit_log/dt=2026-09-15/run1.parquet" {
		t.Fatal(k)
	}
}
