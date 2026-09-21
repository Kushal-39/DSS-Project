// Package collector is the central audit logging consumer (docs/division.md,
// Person 6).
//
// The problem it solves: five components emit structured JSON logs and audit
// events, and the audit pipeline must collect them all without asking any of
// them to change how they log. Components that can push explicitly use the
// ingest API directly; everything else has its container stdout tailed here
// and forwarded, so a service becomes auditable by existing — no code change,
// no library, no per-service configuration.
//
// This file is a minimal Docker Engine API client over the unix socket (raw
// HTTP, no client library): list containers, inspect one, and follow its log
// stream.
package collector

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrContainerGone means the container no longer exists (it was recreated).
// The supervisor treats this as "rediscover and retry", not as a failure.
var ErrContainerGone = errors.New("collector: container is gone")

// maxFrameSize bounds a single multiplexed log frame so a malformed header
// cannot make the collector allocate gigabytes.
const maxFrameSize = 1 << 20

// Container is the subset of a container's summary the collector cares about.
type Container struct {
	ID     string
	Name   string
	Image  string
	Labels map[string]string
}

// Client talks to the Docker Engine API over the unix socket.
type Client struct {
	http       *http.Client
	socketPath string
}

// NewClient returns a client for the given Docker socket path.
func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		http: &http.Client{
			// No client timeout: a followed log stream is long-lived by
			// design. Cancellation comes from the request context.
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "unix", socketPath)
				},
				IdleConnTimeout:       0,
				MaxIdleConnsPerHost:   32,
				ResponseHeaderTimeout: 20 * time.Second,
			},
		},
	}
}

func (c *Client) get(ctx context.Context, path string, query url.Values) (*http.Response, error) {
	endpoint := "http://docker" + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("collector: build docker request: %w", err)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("collector: docker socket %s unreachable: %w", c.socketPath, err)
	}
	if response.StatusCode == http.StatusNotFound {
		response.Body.Close()
		return nil, ErrContainerGone
	}
	if response.StatusCode >= http.StatusBadRequest {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		response.Body.Close()
		return nil, fmt.Errorf("collector: docker %s returned %d: %s",
			path, response.StatusCode, strings.TrimSpace(string(detail)))
	}
	return response, nil
}

// ListContainers returns running containers.
func (c *Client) ListContainers(ctx context.Context) ([]Container, error) {
	response, err := c.get(ctx, "/containers/json", url.Values{"all": {"0"}})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var payload []struct {
		ID     string            `json:"Id"`
		Names  []string          `json:"Names"`
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("collector: decode docker container list: %w", err)
	}

	containers := make([]Container, 0, len(payload))
	for _, item := range payload {
		name := ""
		if len(item.Names) > 0 {
			name = strings.TrimPrefix(item.Names[0], "/")
		}
		containers = append(containers, Container{
			ID:     item.ID,
			Name:   name,
			Image:  item.Image,
			Labels: item.Labels,
		})
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].Name < containers[j].Name })
	return containers, nil
}

// Inspect reports whether the container's log stream is TTY-multiplexed and
// returns its labels.
func (c *Client) Inspect(ctx context.Context, id string) (tty bool, labels map[string]string, err error) {
	response, err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", nil)
	if err != nil {
		return false, nil, err
	}
	defer response.Body.Close()

	var payload struct {
		Config struct {
			Tty    bool              `json:"Tty"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return false, nil, fmt.Errorf("collector: decode docker container inspect: %w", err)
	}
	return payload.Config.Tty, payload.Config.Labels, nil
}

// StreamLogs follows a container's stdout/stderr from `since`, calling emit for
// each complete line. It returns when the stream ends or ctx is cancelled.
//
// `since` is how the collector recovers from a restart without losing the
// decisions that were written while it was down: it re-reads from the last
// known position and the ingest API's idempotency check discards whatever was
// already stored.
func (c *Client) StreamLogs(ctx context.Context, id string, since time.Time, emit func(line []byte)) error {
	tty, _, err := c.Inspect(ctx, id)
	if err != nil {
		return err
	}

	query := url.Values{
		"stdout":     {"1"},
		"stderr":     {"1"},
		"follow":     {"1"},
		"timestamps": {"0"},
	}
	if !since.IsZero() {
		query.Set("since", strconv.FormatInt(since.Unix(), 10))
	}

	response, err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/logs", query)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if tty {
		// A TTY container's logs are not multiplexed, so read them directly.
		return scanLines(ctx, response.Body, emit)
	}

	// Non-TTY: the stream is framed as [stream(1)][padding(3)][size(4,BE)] + payload.
	// Demux through a pipe so line assembly stays a plain bufio.Scanner.
	reader, writer := io.Pipe()
	go func() {
		writer.CloseWithError(demux(response.Body, func(chunk []byte) error {
			_, writeErr := writer.Write(chunk)
			return writeErr
		}))
	}()
	return scanLines(ctx, reader, emit)
}

func scanLines(ctx context.Context, reader io.Reader, emit func(line []byte)) error {
	scanner := bufio.NewScanner(reader)
	// A single audit record can legitimately be a few hundred KB (a request
	// body echoed into a log line). 1 MiB is generous and still bounded.
	scanner.Buffer(make([]byte, 0, 64*1024), maxFrameSize)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		// scanner reuses its buffer, so hand the consumer a copy.
		emit(append([]byte(nil), line...))
	}
	return scanner.Err()
}

func demux(reader io.Reader, emit func(chunk []byte) error) error {
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		size := int(binary.BigEndian.Uint32(header[4:8]))
		switch {
		case size <= 0:
			continue
		case size > maxFrameSize:
			return fmt.Errorf("collector: log frame of %d bytes exceeds the %d byte limit", size, maxFrameSize)
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(reader, payload); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		if err := emit(payload); err != nil {
			return err
		}
	}
}
