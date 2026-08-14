// SPDX-License-Identifier: MIT

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
)

const (
	RouteInventoryVersion = 1
	MaximumRouteBytes     = 64 * 1024
	MaximumRoutePrefixes  = 1024
)

type routeDocument struct {
	Version  int       `json:"version"`
	Prefixes *[]string `json:"prefixes"`
}

func DecodeRouteInventory(data []byte) (StaticRoutes, error) {
	if len(data) == 0 || len(data) > MaximumRouteBytes {
		return nil, errors.New("route inventory size rejected")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, err
	}
	var document routeDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("route inventory shape rejected")
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	if document.Version != RouteInventoryVersion || document.Prefixes == nil {
		return nil, errors.New("route inventory version or prefixes rejected")
	}
	values := *document.Prefixes
	if len(values) > MaximumRoutePrefixes {
		return nil, errors.New("route inventory count rejected")
	}
	result := make(StaticRoutes, 0, len(values))
	for index, value := range values {
		if index > 0 && values[index-1] >= value {
			return nil, errors.New("route inventory ordering rejected")
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 || prefix.String() != value || prefix.Masked() != prefix {
			return nil, errors.New("route inventory prefix rejected")
		}
		for _, prior := range result {
			if prior.Overlaps(prefix) {
				return nil, errors.New("route inventory overlap rejected")
			}
		}
		result = append(result, prefix)
	}
	return result, nil
}

func UnionRoutes(inventories ...RouteInventory) StaticRoutes {
	seen := make(map[netip.Prefix]struct{})
	for _, inventory := range inventories {
		if inventory == nil {
			continue
		}
		for _, prefix := range inventory.Prefixes() {
			if prefix.IsValid() && prefix.Addr().Is4() && prefix.Bits() > 0 {
				seen[prefix.Masked()] = struct{}{}
			}
		}
	}
	result := make(StaticRoutes, 0, len(seen))
	for prefix := range seen {
		result = append(result, prefix)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result
}
