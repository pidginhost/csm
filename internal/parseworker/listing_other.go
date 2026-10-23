//go:build !linux

package parseworker

import (
	"errors"
	"os"
)

func checkListingSeals(*os.File) error {
	return errors.New("parseworker: sealed listings require Linux")
}
