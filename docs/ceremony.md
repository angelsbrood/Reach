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
  EnrollConfirmed{applyPending}                  daemon ──► phone
```

One proof-of-possession signature binds the Secure Enclave identity key
and the WireGuard key — one QR, two keys, literally. The identity key is
Secure-Enclave-resident and the mesh key is kept in the keychain beside
it; both are minted once and reused, so a re-pair brings back the keys the
host already admits and the peer block does not have to be rewritten. The
signature's freshness comes from the daemon's nonce, not from the keys
being new.

The daemon appends the wg peer (the operator applies it: the one visible
sudo) and issues `reach://device/<uuid>`, clientAuth, one year. The first
device enrolled holds the admin grant. The keeper stores the certificate
beside the SE key, installs the tunnel with the system's consent, and
keeps the cluster's calling card (addrs, session port, CA) for its
console.

**The last frame is why "paired" means anything.** `EnrollComplete` says
the phone holds the grant; the peer install waits for it, so a re-pair
that dies at the last step cannot evict the block the phone is still
using. `EnrollConfirmed` closes the other half: without it the phone's
success condition was *"I sent a frame"* while the daemon's was *"I
received one"*, and a stream that died between the two left a phone
reporting a pairing it did not have. The keeper writes nothing and starts
no tunnel until it arrives. `applyPending` is false when the conf already
named this key — nothing was written, so there is no sudo to run — and it
never claims the running interface carries the peer, because the daemon
writes a file and cannot see the interface.

One window remains and is not closable by a further frame: a confirmation
lost in flight leaves the host admitting a key the phone has abandoned.
Both directions recover the same way — pair again — and the difference
from the silence this replaced is that somebody is told.

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

No confirming frame here, and the asymmetry is the point rather than an
oversight. The desk **holds** a ruled verdict, and a re-knock with the same
app key collects it — so an app whose ceremony tears keeps a valid
certificate and converges by asking again. The device half could not do
that: its authorization is a one-time token, spent the moment
`EnrollBegin` arrives, so there was nothing to retry with and nothing to
converge on. A frame the device half needs is one this half would only
duplicate.

**What the app does wait for is the close.** After `EnrollComplete` it
half-closes and then reads until end-of-stream, because the daemon sends
nothing after the grant and half-closes only once it has read that
confirmation — so **EOF is the acknowledgement**, and it costs no frame.
Without that wait the app returned straight into its own teardown, and an
abortive close overtook the confirmation it had just sent: the ceremony
succeeded, the app streamed, and the daemon logged a socket error where
`app enrolled:` belonged. Measured 2026-07-30 at two of four grants on the
rig and seven of ten on loopback. The wait is bounded (2 s) and failing it
costs only the daemon's log line, since the certificate is already in hand
— which is why this is still not a frame the protocol requires.

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
