//go:build !linux

package learnwatch

import (
	"errors"
	"os"

	"github.com/pidginhost/csm/internal/safepath"
)

func metaOf(os.FileInfo) (Meta, bool) { return Meta{}, false }

func lstatAt(*safepath.Dir, string) (os.FileInfo, error) { return nil, errors.ErrUnsupported }
