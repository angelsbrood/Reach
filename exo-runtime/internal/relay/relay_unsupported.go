//go:build !linux

package relay

import (
	"errors"

	"reach.dev/exo-runtime/internal/config"
)

func RunWithSignals(config.Node) error {
	return errors.New("discovery relay requires Linux")
}
