# UIDBATCHES — Future Work

Items deferred from the initial implementation commit (`4353831`).

## Use UIDBATCHES data in subsequent FETCH calls

After receiving `* UIDBATCHES (TAG "...") <uid-ranges>`, the stress tester could issue `UID FETCH <range> FLAGS` (or other fields) per-batch instead of using sequence-number-based ranges. This exercises the primary use case the extension was designed for. Currently the response is stored in `view->last_uidbatches_reply` but not parsed or consumed.

## Verify UIDBATCHES response content

Structural validation is in place: the `(TAG <string>)` correlator is required, matched against the pending UIDBATCHES command, and each range atom is checked for well-formed `<num>:<num>` format with descending order within and across ranges. Semantic content verification is not yet done:

- Actual batch sizes should not exceed the requested batch size (§3.1.3.3.1).
- UID range boundaries should correspond to actual mailbox contents.

## Send invalid UIDBATCHES commands (negative testing)

Scripted tests currently cover reversed ranges and below-minimum batch sizes. Additional edge cases:

- **Batch range spanning >100,000 messages** — should elicit `NO [TOOMANY]` (§3.1.5).
- **Single-batch range `1:1`** — should return only the first batch.
- **Batch range with start = end** — e.g. `5:5`.
- **Very large batch size** — e.g. `UIDBATCHES 999999999` (near UINT_MAX).
- **Extra arguments** — malformed syntax to test BAD responses.
- **UIDBATCHES in non-selected state** — should elicit BAD.

## UIDONLY integration

When imaptest gains UIDONLY mode support ([RFC 9586](https://www.rfc-editor.org/rfc/rfc9586.html)):

- Raise UIDBATCHES probability when UIDONLY is active (§3.3).
- Use UIDBATCHES-ranges exclusively (sequence numbers are forbidden in UIDONLY).
- Ensure FETCH/STORE/SEARCH use UID ranges from UIDBATCHES, not sequence ranges.

## TOOFEW/TOOMANY response code awareness

`imap_client_handle_resp_text_code()` silently ignores unknown codes. While correct today, explicitly handling `TOOFEW` and `TOOMANY` could enable smarter stress-test behavior — e.g., backing off batch sizes on `TOOMANY` or raising them on `TOOFEW` rather than just accepting the NO reply.

## Batch range randomization beyond `1:3`

The stress tester currently sends `1:3` 50% of the time. Could randomize the range based on mailbox message count and batch size to exercise more server paths — e.g., requesting middle or tail batches instead of always the head.