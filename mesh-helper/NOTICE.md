# Reach mesh helper attribution

`reach-meshd` embeds the userspace WireGuard implementation from
[`wireguard-go`](https://git.zx2c4.com/wireguard-go/about/), pinned to annotated
release tag `0.0.20250522`, commit
`f333402bd9cbe0f3eeb02507bd14e23d7d639280`.

WireGuard is a registered trademark of Jason A. Donenfeld. The embedded
implementation is distributed under the MIT license; its copyright and license
notices are retained in the upstream source and Go module cache used to build
the single helper executable.

The Reach-authored Go sources in `mesh-helper/` carry
`SPDX-License-Identifier: MIT` and are distributed under the dedicated
`mesh-helper/LICENSE`. This file-level license is distinct from the repository
root's Apache License 2.0.

The statically linked executable also contains the Go runtime and standard
library. Their license and patent notices are retained with the release notice
inputs used to build the helper.
