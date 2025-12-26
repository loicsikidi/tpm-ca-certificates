package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func JsonCompact(b []byte) ([]byte, error) {
	var compactBuf bytes.Buffer
	if err := json.Compact(&compactBuf, b); err != nil {
		return nil, fmt.Errorf("failed to compact JSON: %w", err)
	}
	return compactBuf.Bytes(), nil
}
