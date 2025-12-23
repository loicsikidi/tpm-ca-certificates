package cli

import (
	"fmt"
	"os"
)

type color string

const (
	colorRed    color = "\033[31m"
	colorGreen  color = "\033[32m"
	colorYellow color = "\033[33m"
	colorReset  color = "\033[0m"
)

func colorize(color color, text string) string {
	return string(color) + text + string(colorReset)
}

func Display(msg string, args ...any) {
	fmt.Println(fmt.Sprintf(msg, args...))
}

func DisplaySuccess(msg string, args ...any) {
	fmt.Println(colorize(colorGreen, fmt.Sprintf(msg, args...)))
	fmt.Println()
}

func DisplayError(msg string, args ...any) {
	fmt.Fprint(os.Stderr, colorize(colorRed, fmt.Sprintf(msg, args...)))
	fmt.Println()
}

func DisplayWarning(msg string, args ...any) {
	fmt.Fprint(os.Stderr, colorize(colorYellow, fmt.Sprintf(msg, args...)))
	fmt.Println()
}

func DisplayStderr(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, msg, args...)
}
