package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAssetName(t *testing.T) {
	u := &Updater{GOOS: "linux", GOARCH: "amd64"}
	got, err := u.assetName("0.3.1")
	if err != nil {
		t.Fatal(err)
	}
	if want := "qw_0.3.1_linux_amd64.tar.gz"; got != want {
		t.Errorf("assetName = %q, want %q", got, want)
	}

	if _, err := (&Updater{GOOS: "windows", GOARCH: "amd64"}).assetName("1.0.0"); err == nil {
		t.Error("expected error for unsupported OS")
	}
	if _, err := (&Updater{GOOS: "linux", GOARCH: "mips"}).assetName("1.0.0"); err == nil {
		t.Error("expected error for unsupported arch")
	}
}

func TestTagAndVersionAndNormalize(t *testing.T) {
	for _, in := range []string{"0.3.1", "v0.3.1"} {
		tag, ver := TagAndVersion(in)
		if tag != "v0.3.1" || ver != "0.3.1" {
			t.Errorf("TagAndVersion(%q) = %q,%q", in, tag, ver)
		}
	}
	if Normalize(" v1.2.3 ") != "1.2.3" {
		t.Errorf("Normalize trimmed wrong: %q", Normalize(" v1.2.3 "))
	}
}

// makeArchive returns a .tar.gz containing a `qw` file with the given content.
func makeArchive(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte(content)
	if err := tw.WriteHeader(&tar.Header{Name: "qw", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// releaseServer serves an asset + checksums.txt under /<tag>/... . badSum swaps in
// a wrong checksum; omitSums serves no checksums.txt (404).
func releaseServer(t *testing.T, tag, asset string, archive []byte, badSum, omitSums bool) *httptest.Server {
	t.Helper()
	sum := sha256hex(archive)
	if badSum {
		sum = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	sums := fmt.Sprintf("%s  %s\n", sum, asset)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + tag + "/" + asset:
			_, _ = w.Write(archive)
		case "/" + tag + "/checksums.txt":
			if omitSums {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(sums))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newUpdater(base string) *Updater {
	return &Updater{HTTPClient: http.DefaultClient, GOOS: "linux", GOARCH: "amd64", DownloadBase: base}
}

func TestDownloadVerifiesAndExtracts(t *testing.T) {
	archive := makeArchive(t, "#!/bin/sh\necho hi\n")
	srv := releaseServer(t, "v0.3.1", "qw_0.3.1_linux_amd64.tar.gz", archive, false, false)
	u := newUpdater(srv.URL)

	binPath, cleanup, err := u.download(t.Context(), "0.3.1")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	got, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "#!/bin/sh\necho hi\n" {
		t.Errorf("extracted content = %q", got)
	}
}

func TestDownloadRejectsBadChecksum(t *testing.T) {
	archive := makeArchive(t, "payload")
	srv := releaseServer(t, "v0.3.1", "qw_0.3.1_linux_amd64.tar.gz", archive, true, false)
	u := newUpdater(srv.URL)

	if _, _, err := u.download(t.Context(), "0.3.1"); err == nil {
		t.Fatal("expected checksum mismatch error")
	}
}

func TestDownloadFailsClosedWithoutChecksums(t *testing.T) {
	archive := makeArchive(t, "payload")
	srv := releaseServer(t, "v0.3.1", "qw_0.3.1_linux_amd64.tar.gz", archive, false, true)
	u := newUpdater(srv.URL)

	if _, _, err := u.download(t.Context(), "0.3.1"); err == nil {
		t.Fatal("expected failure when checksums.txt is missing")
	}
}

func TestServerVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","version":"0.4.2"}`))
	}))
	defer srv.Close()

	u := &Updater{HTTPClient: http.DefaultClient}
	got, err := u.ServerVersion(t.Context(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got != "0.4.2" {
		t.Errorf("ServerVersion = %q, want 0.4.2", got)
	}
}

func TestServerVersionErrorsWhenAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	u := &Updater{HTTPClient: http.DefaultClient}
	if _, err := u.ServerVersion(t.Context(), srv.URL); err == nil {
		t.Fatal("expected error when server reports no version")
	}
}

func TestReplaceBinary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "qw")
	if err := os.WriteFile(target, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	newBin := filepath.Join(dir, "src")
	if err := os.WriteFile(newBin, []byte("NEW"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := replaceBinary(newBin, target); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "NEW" {
		t.Errorf("target content = %q, want NEW", got)
	}
	// The staging file must not be left behind.
	if _, err := os.Stat(filepath.Join(dir, ".qw-upgrade-staged")); !os.IsNotExist(err) {
		t.Error("staging file was left behind")
	}
}
