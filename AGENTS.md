# Reach agent workflow

These standing rules govern work across this repository unless the user explicitly changes them.

## Roles and authority

- Planning owns macro scope, invariants, path and resource ceilings, acceptance gates, and roadmap state.
- Implementation owns ordinary source, test, packaging, and evidence corrections required to converge an opened slice.
- Architecture reviews opening coherence and terminal actual bytes. Its verdict must be an explicit, visible `PASS` or `BLOCK`; silence and packet claims are not verdicts.
- Opening authority covers the normal Planning -> Architecture -> Implementation -> Architecture convergence loop for that slice. Do not ask the user to reauthorize routine handbacks or corrections within the opened scope.

## Convergence loop

1. Planning freezes or authenticates the bounded slice and sends it to Architecture for opening review.
2. An opening `PASS` goes directly to Implementation.
3. An Architecture `BLOCK` is convergence feedback, not a loss of authority. Planning records or clarifies the findings, recuts bounded mechanics or evidence ceilings when needed, and returns the work directly to Implementation.
4. Implementation fixes all in-scope findings and produces a terminal handback with actual-byte evidence.
5. Planning authenticates the live bytes, repository state, path ceilings, hashes, and evidence, then sends the result directly to Architecture for final review.
6. Repeat steps 3-5 until Architecture returns `PASS` or a genuine escalation boundary is reached.

Planning may recut bounded mechanics, resource ceilings, fixtures, and evidence requirements needed to satisfy the already-opened slice. A plan-local phrase such as "separately gated" does not pause this convergence loop unless the user explicitly places the work on hold.

## Handoff reliability

- Continue the exact existing task by task ID when possible and use its displayed title verbatim when identifying it.
- A handoff means sending a clear, user-visible message to the responsible task; Planning does not silently absorb Implementation or Architecture work.
- If cross-task delivery fails and the user pastes a verdict or handback, treat that pasted content as authoritative workflow input, then authenticate live repository bytes before the next terminal handoff.
- Do not create a successor Architecture or Implementation task merely because messaging is unreliable. Create a new task only when the user explicitly requests one.
- Reuse unchanged evidence and require focused proof for changed dependencies or findings; do not restart blanket validation without cause.

## Escalation boundary

Ask the user only for a material macro or scope expansion, a destructive or external action not already authorized, an unavailable required resource or credential, an irreconcilable ownership conflict, or another genuine blocker. Ordinary Architecture findings, plan clarifications, implementation fixes, tests, evidence regeneration, and review handbacks do not require renewed authority.

Commit, push, release, publication, portal changes, and later phases remain separate explicit authorities unless the user has already granted the specific action.

## Repository hygiene

- Preserve `.env.local` and `tasks/` without reading their contents.
- Preserve unrelated user changes and keep staging empty unless a commit has been explicitly authorized.
- Authenticate checkout-sensitive claims from current bytes: status, refs, hashes, path ceilings, and `git diff --check`.
- Report acceptance only to the literal scope proven by the applicable gates.
