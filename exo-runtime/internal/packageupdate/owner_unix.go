package packageupdate

import (
	"os"
	"syscall"
)

func ownerID(info os.FileInfo) int {
	value, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(value.Uid)
}

func linkCount(info os.FileInfo) uint64 {
	value, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(value.Nlink)
}
