// Package selfupdate installs a matching `qw` binary from GitHub Releases. It
// mirrors install.sh: the same asset naming (qw_<ver>_<os>_<arch>.tar.gz) and
// checksums.txt verification, so a `qw upgrade` and a fresh curl-install land on
// byte-identical binaries. Unlike the installer it fails closed if checksums are
// missing — a self-updater must never replace itself with an unverified binary.
package selfupdate

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	defaultRepo = "agarwalvivek29/quickwit-cli"
	binaryName  = "qw"
)

// Updater downloads and installs release binaries. The URL fields and GOOS/GOARCH
// are exported so tests can point at an httptest server and a fixed platform.
type Updater struct {
	HTTPClient   *http.Client
	GOOS, GOARCH string
	// DownloadBase is the release-download base; the asset is fetched from
	// <DownloadBase>/<tag>/<asset>.
	DownloadBase string
	// LatestAPI returns the latest release JSON ({"tag_name": ...}).
	LatestAPI string
}

// New returns an Updater configured for the real GitHub repo and this platform.
func New() *Updater {
	return &Updater{
		HTTPClient:   &http.Client{Timeout: 60 * time.Second},
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		DownloadBase: "https://github.com/" + defaultRepo + "/releases/download",
		LatestAPI:    "https://api.github.com/repos/" + defaultRepo + "/releases/latest",
	}
}

// ServerVersion reads the version a qwproxy endpoint advertises on /health, so an
// upgrade can match the version a context is actually running.
func (u *Updater) ServerVersion(ctx context.Context, endpoint string) (string, error) {
	url := strings.TrimRight(endpoint, "/") + "/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	var doc struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode %s: %w", url, err)
	}
	if doc.Version == "" {
		return "", fmt.Errorf("%s did not report a version (server too old, or not a qwproxy)", url)
	}
	return doc.Version, nil
}

// LatestVersion resolves the newest published release tag.
func (u *Updater) LatestVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.LatestAPI, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolve latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resolve latest release: status %d", resp.StatusCode)
	}
	var doc struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", err
	}
	if doc.TagName == "" {
		return "", fmt.Errorf("latest release has no tag_name")
	}
	return doc.TagName, nil
}

// Run downloads the given version, verifies it, and replaces the running binary.
func (u *Updater) Run(ctx context.Context, version string) error {
	binPath, cleanup, err := u.download(ctx, version)
	if err != nil {
		return err
	}
	defer cleanup()
	return Apply(binPath)
}

// download fetches and verifies the release asset for version, returning the path
// to the extracted binary plus a cleanup func for its temp dir.
func (u *Updater) download(ctx context.Context, version string) (string, func(), error) {
	tag, ver := TagAndVersion(version)
	asset, err := u.assetName(ver)
	if err != nil {
		return "", nil, err
	}

	tmp, err := os.MkdirTemp("", "qw-upgrade-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }

	assetPath := filepath.Join(tmp, asset)
	if err := u.get(ctx, u.DownloadBase+"/"+tag+"/"+asset, assetPath); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("download %s: %w", asset, err)
	}

	sumsPath := filepath.Join(tmp, "checksums.txt")
	if err := u.get(ctx, u.DownloadBase+"/"+tag+"/checksums.txt", sumsPath); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("no checksums.txt for %s; refusing to install an unverified binary", tag)
	}
	if err := verifyChecksum(assetPath, sumsPath, asset); err != nil {
		cleanup()
		return "", nil, err
	}

	binPath, err := extractBinary(assetPath, tmp)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return binPath, cleanup, nil
}

// assetName builds the release asset name for ver on this platform, rejecting
// platforms with no prebuilt binary (matching install.sh's support matrix).
func (u *Updater) assetName(ver string) (string, error) {
	var osName string
	switch u.GOOS {
	case "linux", "darwin":
		osName = u.GOOS
	default:
		return "", fmt.Errorf("unsupported OS %q (prebuilt binaries: linux, darwin) — build from source", u.GOOS)
	}
	var arch string
	switch u.GOARCH {
	case "amd64", "arm64":
		arch = u.GOARCH
	default:
		return "", fmt.Errorf("unsupported architecture %q (prebuilt binaries: amd64, arm64)", u.GOARCH)
	}
	return fmt.Sprintf("%s_%s_%s_%s.tar.gz", binaryName, ver, osName, arch), nil
}

func (u *Updater) get(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(f, resp.Body)
	return err
}

// verifyChecksum computes the SHA-256 of assetPath and requires it to appear
// against assetName in a GoReleaser-style "checksum<space><space>filename" file.
func verifyChecksum(assetPath, sumsPath, assetName string) error {
	f, err := os.Open(assetPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))

	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == assetName {
			if fields[0] == got {
				return nil
			}
			return fmt.Errorf("checksum mismatch for %s", assetName)
		}
	}
	return fmt.Errorf("checksums.txt has no entry for %s", assetName)
}

// extractBinary pulls the `qw` binary out of the .tar.gz into dir and returns its
// path (mode 0755).
func extractBinary(archivePath, dir string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("open archive: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read archive: %w", err)
		}
		if filepath.Base(hdr.Name) != binaryName || hdr.Typeflag != tar.TypeReg {
			continue
		}
		out := filepath.Join(dir, binaryName+"-new")
		w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		// Bound the copy so a malformed archive can't write without limit.
		if _, err := io.Copy(w, io.LimitReader(tr, 512<<20)); err != nil {
			_ = w.Close()
			return "", err
		}
		if err := w.Close(); err != nil {
			return "", err
		}
		return out, nil
	}
	return "", fmt.Errorf("archive did not contain a %q binary", binaryName)
}

// Apply replaces the currently running executable with the binary at newBin.
func Apply(newBin string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return replaceBinary(newBin, exe)
}

// replaceBinary atomically swaps target for the file at newBin. It stages a copy
// in target's directory (so the rename is atomic and on the same filesystem),
// then renames it over target — which works even while target is executing on
// Linux/macOS.
func replaceBinary(newBin, target string) error {
	dir := filepath.Dir(target)
	staged := filepath.Join(dir, ".qw-upgrade-staged")
	if err := copyFile(newBin, staged, 0o755); err != nil {
		return fmt.Errorf("stage new binary in %s (need write permission there?): %w", dir, err)
	}
	if err := os.Rename(staged, target); err != nil {
		_ = os.Remove(staged)
		return fmt.Errorf("replace %s (need write permission to its directory?): %w", target, err)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// TagAndVersion normalizes "0.3.1" or "v0.3.1" into the git tag ("v0.3.1") and
// the bare version ("0.3.1") used in asset names.
func TagAndVersion(v string) (tag, version string) {
	version = strings.TrimPrefix(v, "v")
	return "v" + version, version
}

// Normalize returns a version string comparable across the v-prefix difference.
func Normalize(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}
