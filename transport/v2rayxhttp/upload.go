package v2rayxhttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/sync/errgroup"
)

func (c *Client) upload(ctx context.Context, output net.Conn, id string, g *muxGroup, p *muxPool) error {
	if c.opts.Mode == ModeStreamUp {
		req, err := c.codec.request(ctx, c.opts, c.up, c.opts.Method, id, "", output)
		if err != nil {
			return err
		}
		resp, err := g.send(p, req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}
	// Pipeline bounded, independently numbered POSTs. A missing sequence may
	// arrive after a later one, and request failures cancel the entire stream.
	jobs, postCtx := errgroup.WithContext(ctx)
	window := min(4, int(c.opts.ScMaxBufferedPosts))
	if window == 0 {
		window = 4
	}
	jobs.SetLimit(window)
	step := orRange(c.opts.ScMinPostsIntervalMs, Range{From: 30, To: 30})
	limit := int(rangeRand(c.codec.maxEachPostBytes))
	if c.codec.uplinkDataPlacement == PlacementHeader || c.codec.uplinkDataPlacement == PlacementCookie {
		// Base64 in headers must fit underneath the configured peer's header limit.
		maxHeader := int(c.opts.ServerMaxHeaderBytes)
		if maxHeader == 0 {
			maxHeader = 16 << 10
		}
		limit = min(limit, max(1, (maxHeader-2048)*3/4))
	}
	var last time.Time
	stop := context.AfterFunc(postCtx, func() { output.Close() })
	defer stop()
	// Coalesce writes during the pacing interval instead of issuing one POST
	// per VLESS header or per small socket write.
	buffer := make([]byte, min(limit, 16<<10))
	for seq := uint64(0); ; seq++ {
		n, err := output.Read(buffer)
		if n > 0 {
			until := last.Add(time.Duration(rangeRand(step)) * time.Millisecond)
			if time.Until(until) > 0 {
				output.SetReadDeadline(until)
				for n < limit {
					if n == len(buffer) {
						bigger := make([]byte, min(limit, 2*len(buffer)))
						copy(bigger, buffer)
						buffer = bigger
					}
					m, readErr := output.Read(buffer[n:])
					n += m
					if readErr != nil {
						break
					}
				}
				output.SetReadDeadline(time.Time{})
				if delay := time.Until(until); delay > 0 {
					select {
					case <-time.After(delay):
					case <-postCtx.Done():
					}
				}
			}
			data := bytes.Clone(buffer[:n])
			number := strconv.FormatUint(seq, 10)
			last = time.Now()
			jobs.Go(func() error {
				req, err := c.codec.request(postCtx, c.opts, c.up, c.opts.Method, id, number, nil)
				if err != nil {
					return err
				}
				if !c.codec.encodeUplinkPayload(req, data) {
					req.Body = io.NopCloser(bytes.NewReader(data))
					req.ContentLength = int64(len(data))
				}
				resp, err := g.send(p, req)
				if err != nil {
					return fmt.Errorf("XHTTP upload packet %s: %w", number, err)
				}
				defer resp.Body.Close()
				_, err = io.Copy(io.Discard, resp.Body)
				return err
			})
		}
		if err != nil || postCtx.Err() != nil {
			break
		}
	}
	return jobs.Wait()
}
