# The ceremony

Two enrollments share one channel (`reach-enroll/0`, the sibling QUIC
listener) and one shape — prove a freshly minted key, receive a
certificate scoped by a URI SAN — but they are authorized differently.
A **device** is authorized by a one-time token carried on a QR the
operator reads off their own screen. An **app** is authorized by a
human: its request parks until the keeper's sheet is ruled.

## The device half (one gesture, two keys)

```
reachd pair ──► QR { cluster, name, addrs, port, sport, caHash, token }
keeper scans, then over reach-enroll/0 (server-auth TLS, CA-hash pinned):

  EnrollBegin{token, deviceName}          phone ──► daemon
  EnrollChallenge{nonce}                  daemon ──► phone
  EnrollCertRequest{devicePub, wgPub,
      popSig = SE-sign(nonce‖devicePub‖wgPub)}   phone ──► daemon
  EnrollGrant{deviceCert, caCert, wg{...}}       daemon ──► phone
  EnrollComplete                          phone ──► daemon
```

One proof-of-possession signature binds the Secure Enclave identity key
and the WireGuard key — one QR, two keys, literally. The daemon appends
the wg peer (the operator applies it: the one visible sudo) and issues
`reach://device/<uuid>`, clientAuth, one year. The first device enrolled
holds the admin grant. The keeper stores the certificate beside the SE
key, installs the tunnel with the system's consent, and keeps the
cluster's calling card (addrs, session port, CA) for its console.

## The app half (the grant sheet)

An app holds nothing at first. It discovers the cluster over Bonjour
(`_reach._udp`), reads the CA-hash pin from the TXT record (`ca=`), and
knocks at the enrollment door advertised under the same name
(`_reach-enroll._udp`):

```
  AppEnrollBegin{bundleID, displayName}   app ──► daemon
  EnrollChallenge{nonce}                  daemon ──► app
  AppEnrollCertRequest{appPub,
      popSig = sign(nonce‖appPub)}        app ──► daemon
                ── the request PARKS (120 s window) ──
  GrantEvent{requestID, provenance,
      bundleID, displayName, fingerprint}    daemon ──► keeper (control stream)
  GrantRule{requestID, allow}                keeper ──► daemon
  AppEnrollGrant{appCert, caCert}  — or ErrorFrame(grant-denied / grant-timeout)
  EnrollComplete                          app ──► daemon
```

The keeper's side rides its authenticated session connection: a control
stream opened with the device certificate sends `GrantSubscribe` (admin
device only — the daemon reads the peer leaf's SAN and checks the
registry). Pending requests replay to late subscribers, so the order of
app-knock and keeper-open doesn't matter. The granted certificate reads
`reach://app/<device>/<bundleID>` where `<device>` is the **ruling**
device — the authority the grant hangs from. Certificate issuance is the
grant: any chain-valid certificate may open sessions; revocation and the
ledger are funded scope (M2).

## Named seams (v0, deliberate)

- **The TXT-carried CA pin is provenance TOFU.** It rides the same
  unauthenticated discovery as the address itself. The device ceremony's
  pin is stronger (read off the operator's screen); the app ceremony's
  binding is the human ruling the sheet. Server-side App Attest — proving
  the bundle identity instead of taking it at its word — is the funded
  upgrade, and this seam is where it lands.
- **The sheet's provenance line is observed, not proven**: the remote
  address, upgraded to an enrolled device's name when the registry can
  bind a mesh address. Shown as context for the human, never trusted by
  the daemon.
- **App keys are software P-256 in v0.** The device key is
  Secure-Enclave-resident; per-app SE keys ride with the App Attest
  work.
- **A parked stream idles quietly** — the enrollment channel negotiates
  a 180 s QUIC idle timeout (both ends) so the 120 s grant window fits
  inside it.
