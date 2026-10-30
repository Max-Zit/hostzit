// totp prints the current TOTP code of a base32 secret (development and
// tests of the console sign-in): go run ./tools/totp SECRET
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: totp SECRET")
		os.Exit(2)
	}
	c, err := auth.TOTPCode(os.Args[1], time.Now().Unix()/30)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(c)
}
