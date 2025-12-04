package cli

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// PromptConfirmation prompts the user for choosing yes or no
func PromptConfirmation(question string) bool {
	fmt.Print(question + " (y/n): ")

	// Read single character without requiring Enter
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		// Fallback to regular input if raw mode fails
		var response string
		fmt.Scanln(&response)
		return response == "y" || response == "Y"
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	var buf [1]byte
	_, err = os.Stdin.Read(buf[:])
	if err != nil {
		return false
	}

	// Echo the character and newline
	fmt.Printf("%c\n", buf[0])

	return buf[0] == 'y' || buf[0] == 'Y'
}
