package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client talks to the control plane of a running weed
type Client struct {
	socket string
	http   *http.Client
}

// NewClient returns a client of the control plane listening at socket
func NewClient(socket string) *Client {
	return &Client{socket: socket, http: &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}}
}

// Do sends a request with in as its JSON body (if not nil), and decodes the JSON
// answer into out (if not nil). Answers other than 2xx are errors, with the message
// of weed.
func (c *Client) Do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://weed"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ue := (*url.Error)(nil); errors.As(err, &ue) {
			if ue.Timeout() {
				return fmt.Errorf("weed's control plane at %s did not answer within %v: what was asked may have been done; weed's log says", c.socket, c.http.Timeout)
			}
			err = ue.Err // without the URL, which is not the socket's
		}
		return fmt.Errorf("cannot reach weed's control plane at %s (is weed running there? -socket or -config names another): %w", c.socket, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e Error
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("weed: %s", e.Error)
		}
		return fmt.Errorf("weed answered %s", resp.Status)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
