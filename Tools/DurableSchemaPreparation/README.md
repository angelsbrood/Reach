# Durable schema preparation (S90)

This offline composition selects `s90-public-chat-schema-v1` on S89's existing
request preparer. The default remains `s89-public-chat-tools-v1`, with its original
encoded descriptor, request identities and ordinary/required preparation.

The new revision admits a portable response schema only with no tools, no
reasoning, nil/allowed/disallowed tool mode, and explicitly false
`includeSchemaInPrompt`. Sampling is nil/greedy, temperature nil/zero and maximum
0...512 (default 512). Non-guided context controls retain S89's nil-only policy.
The owner attests the revision against actual local artifacts; a peer cannot
select a revision by naming a model.

The response schema crosses the RC1 throwing extraction boundary and shares the
whole request's 64 KiB, 8,192-node and depth-32 limits. The same public chat/template
path produces 1...2,048 tokens without schema prompt injection. Canonical schema
bytes become the existing guided specification. Object schema documents may
constrain scalar or array JSON roots. Stored validation checks the selected native
identity, tokens, canonical schema, grammar/tokenizer/vocabulary/codec/options and
stable IDs before attach/acceptance; it does not reconstruct a request preimage.

Declaration assessment does not compile a grammar. Native incompatibility may
follow accepted begin and model factory evaluation, while still preceding prefill.
The harness demonstrates that timing with a portable lookahead regex rejected by
the selected compiler. This does not claim arbitrary schema support.

Run against the authenticated canonical S89 baseline with the local pinned
checkouts and Metal artifact already present:

```sh
python3 Tools/DurableSchemaPreparation/run.py --repo /Users/nellymoon/Documents/Swift/Reach
```

The runner copies selected sources into owned private scratch, composes the same
35 native outputs, builds with four jobs and runs serial focused tests/workers.
It uses known non-secret fixture keys and guarded S89/S88 disk roots; no Keychain
API, network, old worker campaign or shipping runtime is invoked. The portable
client/policy linkage is checked for absence of MLX symbols.

The real two-layer tiny-Llama proof includes a long constrained object reference,
a nonterminal checkpoint with visible text, a fresh selected-disk continuation,
a distinct integer constraint, scalar root, and zero/short budget non-success.
Fresh worker argv contains only mode/root/output. Oracles are read after positive
fresh work and process exit. Exact bindings, original context/reference, complete
batches/events and native input/cache-offset suffixes are compared; logits use
rtol 1e-5 and atol 1e-6. Request preparation, template/request tokenization, entry
encodes, issue/begin and repeated prefill are zero; native grammar encodes are
separate. Accepted EOS supplies one usage/complete tail; cancellation and incomplete
mapping remain the existing provider behavior.

The runner retains ordinary logs, full bounded native snapshots, copied source
bindings, test counts, direct child joins and sampled resource observations. It
removes owned source/build/fixture trees at settlement, including failed attempts.
This is no new crash, crypto, Keychain, deep native-state or effect campaign; those
unchanged layers retain their accepted evidence. Shipping offers stay [1,0] and
opt-in/readiness remain off by default. There is no production loader or adoption.
