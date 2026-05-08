package utils

import "net/http"

// HTTPClient defines the interface for an HTTP client.
//
// It is used essentially to allow for easier testing and mocking of HTTP requests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}
