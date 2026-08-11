// SPDX-License-Identifier: MIT

package mesh

type Backend interface {
	Apply(Specification) (string, error)
	Close() error
}
