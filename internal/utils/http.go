package utils

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
)

var (
	ErrHTTPGetTooLarge = fmt.Errorf("downloaded content exceeds maximum allowed size")
	ErrHTTPGetError    = fmt.Errorf("error during HTTP GET request")
)

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func HttpGET(client HttpClient, url string, otionalMaxLength ...int64) ([]byte, error) {
	maxLength, err := OptionalArg(otionalMaxLength)
	if err != nil {
		maxLength = DefaultMaxFileSize
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err := fmt.Errorf("failed to download from %s: HTTP %d", url, res.StatusCode)
		return nil, fmt.Errorf("%w: %v", ErrHTTPGetError, err)
	}

	var length int64
	if header := res.Header.Get("Content-Length"); header != "" {
		length, err = strconv.ParseInt(header, 10, 0)
		if err != nil {
			return nil, err
		}
		if length > maxLength {
			err := fmt.Errorf("download failed for %s, length %d is larger than expected %d", url, length, maxLength)
			return nil, fmt.Errorf("%w: %v", ErrHTTPGetTooLarge, err)
		}
	}
	// Although the size has been checked above, use a LimitReader in case
	// the reported size is inaccurate.
	data, err := io.ReadAll(io.LimitReader(res.Body, maxLength+1))
	if err != nil {
		return nil, err
	}

	length = int64(len(data))
	if int64(length) > maxLength {
		err := fmt.Errorf("download failed for %s, length %d is larger than expected %d", url, length, maxLength)
		return nil, fmt.Errorf("%w: %v", ErrHTTPGetTooLarge, err)
	}
	return data, nil
}
