package cli

import "testing"

func Test_colorize(t *testing.T) {
	tests := []struct {
		name     string
		color    color
		text     string
		expected string
	}{
		{
			name:     "red color",
			color:    colorRed,
			text:     "Error message",
			expected: "\033[31mError message\033[0m",
		},
		{
			name:     "green color",
			color:    colorGreen,
			text:     "Success message",
			expected: "\033[32mSuccess message\033[0m",
		},
		{
			name:     "empty text",
			color:    colorRed,
			text:     "",
			expected: "\033[31m\033[0m",
		},
		{
			name:     "text with special characters",
			color:    colorGreen,
			text:     "✅ Verification succeeded",
			expected: "\033[32m✅ Verification succeeded\033[0m",
		},
		{
			name:     "multiline text",
			color:    colorRed,
			text:     "Line 1\nLine 2",
			expected: "\033[31mLine 1\nLine 2\033[0m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := colorize(tt.color, tt.text)
			if result != tt.expected {
				t.Errorf("colorize() = %q, want %q", result, tt.expected)
			}
		})
	}
}
