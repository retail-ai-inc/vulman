package nvddb

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"vulman/internal/apperror"
)

const downloadFile = ".vulman-nvd-download"
const maxFeedSize int64 = 16 << 30
const maxCompressedSize int64 = 2 << 30

type statusError int

func (e statusError) Error() string { return fmt.Sprintf("NVD download returned HTTP %d", e) }

func (e statusError) PublicMessage() apperror.Message {
	return apperror.Newf("nvd_download_http", "NVD download returned HTTP %d", int(e)).PublicMessage()
}

func parseMeta(data []byte, f Feed) (Feed, error) {
	values := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if ok {
			values[key] = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return Feed{}, err
	}
	at, err := time.Parse(time.RFC3339Nano, values["lastModifiedDate"])
	if err != nil {
		return Feed{}, apperror.New("invalid_nvd_feed_timestamp", "invalid NVD feed timestamp")
	}
	f.At = at.UTC()
	f.SHA = strings.ToLower(values["sha256"])
	hash, err := hex.DecodeString(f.SHA)
	if err != nil || len(hash) != sha256.Size {
		return Feed{}, apperror.New("invalid_nvd_feed_sha_256", "invalid NVD feed SHA-256")
	}
	f.Size, err = strconv.ParseInt(values["size"], 10, 64)
	if err != nil || f.Size <= 0 || f.Size > maxFeedSize {
		return Feed{}, apperror.New("invalid_nvd_feed_size", "invalid NVD feed size")
	}
	key := "gzSize"
	if f.Kind == "cpe" {
		key = "zipSize"
	}
	f.Compressed, err = strconv.ParseInt(values[key], 10, 64)
	if err != nil || f.Compressed <= 0 || f.Compressed > maxCompressedSize {
		return Feed{}, apperror.New("invalid_compressed_nvd_feed_size", "invalid compressed NVD feed size")
	}
	return f, nil
}

func (u *Updater) get(ctx context.Context, endpoint string, consume func(*http.Response) error) error {
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "Vulman-NVD-Sync/1.0")
		resp, err := u.HTTP.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusOK {
			err = consume(resp)
			return errors.Join(err, resp.Body.Close())
		}
		status := resp.StatusCode
		delay := time.Duration(1<<attempt) * time.Second
		if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 {
			if seconds > 30 {
				_ = resp.Body.Close()
				return apperror.New("nvd_feed_service_is_cooling_down_retry_later", "NVD feed service is cooling down; retry later")
			}
			delay = time.Duration(seconds) * time.Second
		} else if at, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil && time.Until(at) > delay {
			delay = time.Until(at)
		}
		if err := resp.Body.Close(); err != nil {
			return err
		}
		if (status != 429 && status != 503 && status != 502 && status != 504) || attempt == 2 || delay > 30*time.Second {
			return statusError(status)
		}
		u.progress("waiting", 0, 0)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return apperror.New("nvd_download_failed", "NVD download failed")
}

func (u *Updater) metadata(ctx context.Context, f Feed) (Feed, error) {
	var result Feed
	err := u.get(ctx, f.MetaURL, func(resp *http.Response) error {
		data, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
		if err != nil {
			return err
		}
		if len(data) > 64<<10 {
			return apperror.New("nvd_metadata_exceeds_size_limit", "NVD metadata exceeds size limit")
		}
		result, err = parseMeta(data, f)
		return err
	})
	return result, err
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

// streams reads every JSON member of the dictionary ZIP. The hash spans their
// uncompressed bytes in archive order, matching the NVD metadata contract.
func (u *Updater) streams(ctx context.Context, f Feed, visit func(io.Reader) error) error {
	file, err := u.store.root.Open(downloadFile)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if f.Kind == "nvd" {
		reader, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		err = visit(&contextReader{ctx: ctx, reader: reader})
		return errors.Join(err, reader.Close())
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	z, err := zip.NewReader(file, info.Size())
	if err != nil {
		return err
	}
	var total uint64
	count := 0
	for _, member := range z.File {
		if !strings.HasSuffix(member.Name, ".json") {
			continue
		}
		if member.UncompressedSize64 > uint64(maxFeedSize)-total {
			return apperror.New("expanded_cpe_dictionary_exceeds_size_limit", "expanded CPE dictionary exceeds size limit")
		}
		total += member.UncompressedSize64
		reader, err := member.Open()
		if err != nil {
			return err
		}
		err = visit(&contextReader{ctx: ctx, reader: reader})
		if err := errors.Join(err, reader.Close()); err != nil {
			return err
		}
		count++
	}
	if count == 0 {
		return apperror.New("cpe_dictionary_has_no_json_chunks", "CPE dictionary has no JSON chunks")
	}
	return nil
}

func (u *Updater) verify(ctx context.Context, f Feed) error {
	info, err := u.store.root.Stat(downloadFile)
	if err != nil {
		return err
	}
	if info.Size() != f.Compressed {
		return apperror.New("nvd_compressed_download_size_mismatch", "NVD compressed download size mismatch")
	}
	hash := sha256.New()
	var size int64
	err = u.streams(ctx, f, func(reader io.Reader) error {
		n, err := io.Copy(hash, io.LimitReader(reader, maxFeedSize-size+1))
		size += n
		if size > maxFeedSize {
			return apperror.New("nvd_uncompressed_feed_exceeds_size_limit", "NVD uncompressed feed exceeds size limit")
		}
		return err
	})
	if err != nil {
		return err
	}
	if size != f.Size || hex.EncodeToString(hash.Sum(nil)) != f.SHA {
		return apperror.New("nvd_feed_integrity_failed", "NVD uncompressed size or SHA-256 verification failed; retry after the feed and metadata agree")
	}
	return nil
}

func (u *Updater) download(ctx context.Context, f Feed) error {
	u.progress("verifying", 0, f.Compressed)
	if err := u.verify(ctx, f); err == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	u.progress("downloading", 0, f.Compressed)
	if err := u.get(ctx, f.URL, func(resp *http.Response) error {
		file, err := u.store.root.OpenFile(downloadFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		reader := &contextReader{ctx: ctx, reader: resp.Body, report: func(n int64) { u.progress("downloading", n, f.Compressed) }}
		n, err := io.Copy(file, io.LimitReader(reader, f.Compressed+1))
		if err == nil && n != f.Compressed {
			err = apperror.New("nvd_download_is_incomplete", "NVD download is incomplete")
		}
		if err == nil {
			err = file.Sync()
		}
		return errors.Join(err, file.Close())
	}); err != nil {
		return err
	}
	u.progress("verifying", f.Compressed, f.Compressed)
	return u.verify(ctx, f)
}

// budgetReader bounds each decoded value, including while resuming a large
// stream. json.Decoder may buffer ahead, but never gets an unbounded input read.
type budgetReader struct {
	reader        io.Reader
	read, ceiling int64
}

func (r *budgetReader) Read(p []byte) (int, error) {
	left := r.ceiling - r.read
	if left <= 0 {
		return 0, apperror.New("nvd_json_value_exceeds_size_limit", "NVD JSON value exceeds size limit")
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, err := r.reader.Read(p)
	r.read += int64(n)
	return n, err
}

type arrayInfo struct {
	Count           int
	Total, Expected *int
}

func readArray(reader io.Reader, key string, info *arrayInfo, visit func(json.RawMessage) error) error {
	limited := &budgetReader{reader: reader, ceiling: 8 << 20}
	dec := json.NewDecoder(limited)
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return apperror.New("invalid_nvd_json_envelope", "invalid NVD JSON envelope")
	}
	found := false
	for dec.More() {
		limited.ceiling = dec.InputOffset() + (8 << 20)
		token, err := dec.Token()
		if err != nil {
			return err
		}
		switch token {
		case key:
			if found {
				return apperror.New("duplicate_nvd_record_array", "duplicate NVD record array")
			}
			found = true
			start, err := dec.Token()
			if err != nil || start != json.Delim('[') {
				return apperror.New("invalid_nvd_record_array", "invalid NVD record array")
			}
			for dec.More() {
				limited.ceiling = dec.InputOffset() + (8 << 20)
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					return err
				}
				if len(raw) > 8<<20 {
					return apperror.New("nvd_record_exceeds_size_limit", "NVD record exceeds size limit")
				}
				info.Count++
				if err := visit(raw); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
		case "totalResults", "resultsPerPage":
			var count int
			if err := dec.Decode(&count); err != nil || count < 0 {
				return apperror.New("invalid_nvd_feed_record_count", "invalid NVD feed record count")
			}
			if token == "totalResults" {
				info.Total = &count
			} else {
				info.Expected = &count
			}
		default:
			var ignored json.RawMessage
			if err := dec.Decode(&ignored); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if !found {
		return apperror.New("nvd_feed_is_missing_its_record_array", "NVD feed is missing its record array")
	}
	if info.Total == nil || info.Expected == nil || info.Count != *info.Expected {
		return apperror.New("nvd_feed_record_count_does_not_match_its_envelope", "NVD feed record count does not match its envelope")
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return apperror.New("nvd_feed_has_trailing_or_malformed_json", "NVD feed has trailing or malformed JSON")
	}
	return nil
}
