package osvdb

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"vulman/internal/apperror"
)

const archiveFile = ".vulman-osv-download.zip"
const indexFile = ".vulman-osv-index.csv"
const maxArchiveSize int64 = 2 << 30
const maxIndexSize int64 = 256 << 20
const maxRecordSize int64 = 8 << 20

var generationID = regexp.MustCompile(`^[0-9]{1,30}$`)

type httpError int

func (e httpError) PublicMessage() apperror.Message {
	return apperror.Newf("osv_download_http", "OSV download returned HTTP %d", int(e)).PublicMessage()
}

func (e httpError) Error() string {
	return fmt.Sprintf("OSV download returned HTTP %d", e)
}

func checksum(header http.Header) (string, error) {
	for _, entry := range header.Values("X-Goog-Hash") {
		for _, part := range strings.Split(entry, ",") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(part), "crc32c="); ok {
				data, err := base64.StdEncoding.DecodeString(value)
				if err == nil && len(data) == 4 {
					return value, nil
				}
			}
		}
	}

	return "", apperror.New("osv_object_has_no_valid_crc32c_checksum", "OSV object has no valid CRC32C checksum")
}

func (u *Updater) endpoint(name string) string {
	return u.baseURL + "/" + strings.ReplaceAll(url.PathEscape(name), "%2F", "/")
}

func (u *Updater) request(ctx context.Context, method, endpoint string, consume func(*http.Response) error) error {
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
		if err != nil {
			return err
		}

		req.Header.Set("User-Agent", "Vulman-OSV-Sync/1.0")
		req.Header.Set("Accept-Encoding", "identity")
		resp, err := u.HTTP.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode == http.StatusOK {
			return errors.Join(consume(resp), resp.Body.Close())
		}

		status := resp.StatusCode
		delay := time.Duration(1<<attempt) * time.Second
		if value := resp.Header.Get("Retry-After"); value != "" {
			if seconds, err := strconv.ParseInt(value, 10, 32); err == nil && seconds > 0 {
				delay = time.Duration(seconds) * time.Second
			} else if at, err := http.ParseTime(value); err == nil && time.Until(at) > delay {
				delay = time.Until(at)
			}
		}

		if err := resp.Body.Close(); err != nil {
			return err
		}

		if attempt == 2 || delay > 30*time.Second || (status != 429 && status != 502 && status != 503 && status != 504) {
			return httpError(status)
		}

		u.phase("waiting", 0, 0, 0)
		if err := wait(ctx, delay); err != nil {
			return err
		}
	}

	return apperror.New("osv_download_failed", "OSV download failed")
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (u *Updater) head(ctx context.Context, name string, limit int64) (blob, error) {
	object := blob{Name: name}
	err := u.request(ctx, http.MethodHead, u.endpoint(name), func(resp *http.Response) error {
		object.Size = resp.ContentLength
		object.Generation = resp.Header.Get("X-Goog-Generation")
		if object.Size <= 0 || object.Size > limit || !generationID.MatchString(object.Generation) {
			return apperror.New("invalid_osv_object_size_or_generation", "invalid OSV object size or generation")
		}

		var err error
		object.CRC, err = checksum(resp.Header)
		if err != nil {
			return err
		}

		object.Updated, err = http.ParseTime(resp.Header.Get("Last-Modified"))
		return err
	})

	return object, err
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
	read   int64
	report func(int64)
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	n, err := r.reader.Read(p)
	r.read += int64(n)
	if r.report != nil {
		r.report(r.read)
	}

	return n, err
}

func matchesChecksum(reader io.Reader, expected string) error {
	hash := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	if _, err := io.Copy(hash, reader); err != nil {
		return err
	}

	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], hash.Sum32())
	if base64.StdEncoding.EncodeToString(sum[:]) != expected {
		return apperror.New("osv_crc32c_checksum_mismatch", "OSV CRC32C checksum mismatch")
	}

	return nil
}

func (u *Updater) verified(ctx context.Context, filename string, object blob) bool {
	f, err := u.store.root.Open(filename)
	if err != nil {
		return false
	}

	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || info.Size() != object.Size {
		return false
	}

	return matchesChecksum(&contextReader{ctx: ctx, reader: f}, object.CRC) == nil
}

func (u *Updater) download(ctx context.Context, object blob, filename string) error {
	u.phase("verifying", 0, object.Size, 0)
	if u.verified(ctx, filename, object) {
		return nil
	}

	u.phase("downloading", 0, object.Size, 0)
	endpoint := u.endpoint(object.Name) + "?generation=" + object.Generation
	err := u.request(ctx, http.MethodGet, endpoint, func(resp *http.Response) error {
		if resp.Header.Get("X-Goog-Generation") != object.Generation {
			return apperror.New("osv_object_generation_changed_during_download", "OSV object generation changed during download")
		}

		f, err := u.store.root.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}

		reader := &contextReader{ctx: ctx, reader: resp.Body, report: func(n int64) { u.phase("downloading", n, object.Size, 0) }}
		n, err := io.Copy(f, io.LimitReader(reader, object.Size+1))
		if err == nil && n != object.Size {
			err = apperror.New("osv_download_is_incomplete", "OSV download is incomplete")
		}

		if err == nil {
			err = f.Sync()
		}

		return errors.Join(err, f.Close())
	})
	if err != nil {
		return err
	}

	u.phase("verifying", object.Size, object.Size, 0)
	if !u.verified(ctx, filename, object) {
		if err := ctx.Err(); err != nil {
			return err
		}

		return apperror.New("osv_download_checksum_verification_failed", "OSV download checksum verification failed")
	}

	return nil
}
