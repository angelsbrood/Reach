# Relay route inventory

`/etc/reach-relay-hub/routes.json` is operator-owned intent. It is not created
by the package. Before enabling the service, install a root-owned,
`reach-relay`-group-owned regular file with mode `0640` and this strict shape:

```json
{
  "version": 1,
  "prefixes": [
    "192.0.2.0/24"
  ]
}
```

Prefixes are canonical, nonzero IPv4 networks in strict lexical order. They
must be unique and nonoverlapping. The service unions this declaration with
read-only routes from every current Linux IPv4 routing table on startup and
every reload. A relay `/24` that overlaps either source is refused before any
WireGuard peer mutation.

The package deliberately installs no configuration, keys, firewall policy,
fixtures, or network state. The operator remains responsible for those files
and for a firewall restricted to the configured relay peers.
