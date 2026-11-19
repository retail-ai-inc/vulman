package testutil

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// OSVTransport serves a verified ecosystem snapshot without contacting OSV.
type OSVTransport struct {
	Objects map[string][]byte
	Before  func(*http.Request) error
}

func NewOSVTransport(t *testing.T, ecosystem string, rows []json.RawMessage) *OSVTransport {
	t.Helper()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	objects := map[string][]byte{}
	var index strings.Builder
	for _, raw := range rows {
		var record struct {
			ID       string
			Modified time.Time
		}
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}

		entry, err := writer.Create(record.ID + ".json")
		if err != nil {
			t.Fatal(err)
		}

		if _, err := entry.Write(raw); err != nil {
			t.Fatal(err)
		}

		if _, err := fmt.Fprintf(&index, "%s,%s\n", record.Modified.Format(time.RFC3339Nano), record.ID); err != nil {
			t.Fatal(err)
		}

		objects[ecosystem+"/"+record.ID+".json"] = bytes.Clone(raw)
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	objects[ecosystem+"/all.zip"] = archive.Bytes()
	objects[ecosystem+"/modified_id.csv"] = []byte(index.String())
	return &OSVTransport{Objects: objects}
}

func (f *OSVTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.Before != nil {
		if err := f.Before(r); err != nil {
			return nil, err
		}
	}

	name := strings.TrimPrefix(r.URL.Path, "/osv-vulnerabilities/")
	data, found := f.Objects[name]
	header := make(http.Header)
	header.Set("X-Goog-Generation", "1")
	header.Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
	header.Set("X-Goog-Hash", "crc32c="+base64.StdEncoding.EncodeToString(sum[:]))
	status := http.StatusOK
	if !found {
		status = http.StatusNotFound
	}

	body := data
	if r.Method == http.MethodHead {
		body = nil
	}

	return &http.Response{StatusCode: status, Header: header, ContentLength: int64(len(data)), Body: io.NopCloser(bytes.NewReader(body))}, nil
}
