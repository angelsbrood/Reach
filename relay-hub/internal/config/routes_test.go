// SPDX-License-Identifier: MIT

package config_test

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"systems.reach/relay-hub/internal/config"
)

func TestDecodeRouteInventory(t *testing.T) {
	routes, err := config.DecodeRouteInventory([]byte(`{"version":1,"prefixes":["10.0.0.0/8","192.0.2.0/24"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(routes); got != "[10.0.0.0/8 192.0.2.0/24]" {
		t.Fatalf("routes = %s", got)
	}
}

func TestRouteInventoryStrictRefusals(t *testing.T) {
	cases := map[string]string{
		"missing":       `{"version":1}`,
		"version":       `{"version":2,"prefixes":[]}`,
		"unknown":       `{"version":1,"prefixes":[],"extra":true}`,
		"duplicate key": `{"version":1,"prefixes":[],"prefixes":[]}`,
		"trailing":      `{"version":1,"prefixes":[]} true`,
		"ipv6":          `{"version":1,"prefixes":["fd00::/8"]}`,
		"default":       `{"version":1,"prefixes":["0.0.0.0/0"]}`,
		"noncanonical":  `{"version":1,"prefixes":["192.0.2.1/24"]}`,
		"duplicate":     `{"version":1,"prefixes":["192.0.2.0/24","192.0.2.0/24"]}`,
		"unsorted":      `{"version":1,"prefixes":["192.0.2.0/24","10.0.0.0/8"]}`,
		"overlap":       `{"version":1,"prefixes":["10.0.0.0/8","10.87.0.0/24"]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := config.DecodeRouteInventory([]byte(raw)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := config.DecodeRouteInventory([]byte(`{"version":1,"prefixes":["` + strings.Repeat("1", config.MaximumRouteBytes) + `"]}`)); err == nil {
		t.Fatal("oversized input accepted")
	}
	tooMany := make([]string, config.MaximumRoutePrefixes+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("198.%d.%d.%d/32", i/65536, (i/256)%256, i%256)
	}
	raw, _ := json.Marshal(map[string]any{"version": 1, "prefixes": tooMany})
	if _, err := config.DecodeRouteInventory(raw); err == nil {
		t.Fatal("excessive route count accepted")
	}
}

func TestUnionRoutesDeduplicatesAndSorts(t *testing.T) {
	got := config.UnionRoutes(
		config.StaticRoutes{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("10.0.0.0/8")},
		config.StaticRoutes{netip.MustParsePrefix("10.0.0.0/8")},
	)
	if fmt.Sprint(got) != "[10.0.0.0/8 192.0.2.0/24]" {
		t.Fatalf("union = %v", got)
	}
}
