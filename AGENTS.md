# Reach agent workflow

These standing rules govern work across this repository unless the user explicitly changes them.

## Roles and authority

- Planning owns macro scope, invariants, path and resource ceilings, acceptance gates, and roadmap state.
- Implementation owns ordinary source, test, packaging, and evidence corrections required to converge an opened slice.
- Architecture reviews material opening decisions when warranted and terminal actual bytes. Its verdict must be an explicit, visible `PASS` or `BLOCK`; silence and packet claims are not verdicts.
- Opening authority covers the normal convergence loop for that slice. Do not ask the user to reauthorize routine handbacks or corrections within the opened scope.

## Proportionate process

- Fit requirements, evidence and review depth to the actual context and consequence of failure. Move briskly on local procedural bug fixes; do not turn them into security or formal-verification projects without a concrete need.
- Use the smallest adequate loop: a clear outcome and scope, implementation, focused tests and a concise review. Separate opening review is for material architecture/risk decisions or an explicit user request, not a ritual for every fix or plan clarification.
- Check feasibility of a critical platform assumption before making it an acceptance gate. Do not demand stronger guarantees than the task needs, such as exhaustive opaque-tool descendant history for ordinary build/test supervision. State observation limits honestly.
- Ordinary failed builds/tests are inputs to correction and retry, not spent one-shot opportunities or terminal slices. Do not impose fixed attempt budgets, source-sealing machinery, bespoke evidence ledgers or repeated full-suite passes unless the actual risk justifies them.
- Prefer existing tests, ordinary logs and concise actual-byte evidence. Hash artifacts when needed to bind a result; do not repeatedly seal unchanged planning documents or re-review administrative acknowledgements. A finding must identify a relevant defect or risk, not merely missing ceremony.
- Preserve genuine safety, privacy, ownership and external-action boundaries. Proportionality narrows unnecessary proof obligations; it does not justify false success claims or ignoring known failures.

## Convergence loop

1. Planning defines or authenticates the bounded outcome and any necessary constraints. Send material opening decisions to Architecture when warranted or explicitly requested; otherwise route the authorized fix directly to Implementation.
2. When opening review is required, its `PASS` goes directly to Implementation. Do not repeat it for routine clarifications or an explicitly authorized removal of an unnecessary requirement.
3. An Architecture `BLOCK` is convergence feedback, not a loss of authority. Planning records or clarifies the findings, recuts bounded mechanics or evidence ceilings when needed, and returns the work directly to Implementation.
4. Implementation fixes all in-scope findings and produces a concise terminal handback with actual-byte evidence proportionate to the change.
5. Planning authenticates the actual changed bytes, repository state and relevant evidence, then sends the result directly to Architecture for focused final review. Reuse unchanged evidence instead of duplicating the full validation effort.
6. Repeat steps 3-5 until Architecture returns `PASS` or a genuine escalation boundary is reached.
7. After terminal Architecture `PASS` and Planning closeout, commit the accepted, in-scope changes and push the intended branch as the final step. This is standing authorization; do not ask for another commit/push approval unless the user has explicitly withheld that step.

Planning may recut bounded mechanics, resource ceilings, fixtures, and evidence requirements needed to satisfy the already-opened slice. A plan-local phrase such as "separately gated" does not pause this convergence loop unless the user explicitly places the work on hold.

## Handoff reliability

- Continue the exact existing task by task ID when possible and use its displayed title verbatim when identifying it.
- A handoff means sending a clear, user-visible message to the responsible task; Planning does not silently absorb Implementation or Architecture work.
- After a successful handoff, silently await the receiving task's handback by default. Do not routinely poll, inspect progress, or narrate waiting; monitor only when there is a clear situational requirement to do so.
- If cross-task delivery fails and the user pastes a verdict or handback, treat that pasted content as authoritative workflow input, then authenticate live repository bytes before the next terminal handoff.
- Do not create a successor Architecture or Implementation task merely because messaging is unreliable. Create a new task only when the user explicitly requests one.
- Reuse unchanged evidence and require focused proof for changed dependencies or findings; do not restart blanket validation without cause.

## Escalation boundary

Ask the user only for a material macro or scope expansion, a destructive or external action not already authorized, an unavailable required resource or credential, an irreconcilable ownership conflict, or another genuine blocker. Ordinary Architecture findings, plan clarifications, implementation fixes, tests, evidence regeneration, and review handbacks do not require renewed authority.

The post-closeout commit/push in step 7 is authorized even where older plan text calls for separate approval. Commit/push before that point or outside the accepted scope, release, publication, portal changes, and later phases still require their own explicit authority.

## Repository hygiene

- Preserve `.env.local` and `tasks/` without reading their contents.
- Preserve unrelated user changes and keep staging empty until an authorized commit, including the post-closeout commit in step 7. Stage only the intended, in-scope changes; keep ignored/private planning and evidence unpublished.
- Authenticate checkout-sensitive claims from current bytes: status, refs, hashes, path ceilings, and `git diff --check`.
- Report acceptance only to the literal scope proven by the applicable gates.
