# Task 2 TDD log

Test counts are named Rust tests (table rows are additional assertions). RED compile errors are intentional missing APIs, never unrelated syntax failures. Full cargo output is retained locally in `.lane/tdd/`. The initial RED includes only its test and Cargo test-runner metadata; production source begins in GREEN. Pcap will be an optional feature per task 2, overriding the plan's default-backend build choice, using the planned dynamic loader and exact dependency pins.

- 01 envelope RED — 1 test; missing library/envelope API, cargo test failed as intended.
- 01 envelope GREEN — 1 passed; checked borrowed envelopes, Ethernet padding and payload bounds; no router state yet.
- 02 nd-validation RED — 2 tests specified; cargo test failed for the new contract (see paired test commit).
- 02 nd-validation GREEN — 2 passed; Shared ND validation rejects a malformed final TLV before any consumer can update state; transit fragment metadata is separate.
- 03 pio RED — 3 tests specified; cargo test failed for the new contract (see paired test commit).
- 03 pio GREEN — 3 passed; Lifetime admission uses the received preferred value; non-/64 on-link evidence remains available for routing.
- 04 route-options RED — 4 tests specified; cargo test failed for the new contract (see paired test commit).
- 04 route-options GREEN — 4 passed; Reserved RIO preference and PREF64 PLC are ignored per option; valid neighboring options survive.
- 05 ra-encoding RED — 5 tests specified; cargo test failed for the new contract (see paired test commit).
- 05 ra-encoding GREEN — 5 passed; Golden expectations use independent fixture assembly and checksum; no deferred service options emitted.
- 06 ra-timers RED — 6 tests specified; cargo test failed for the new contract (see paired test commit).
- 06 ra-timers GREEN — 6 passed; Monotonic milliseconds and finite/infinite lifetimes; scripted entropy and unbiased production sampling; scheduler keeps only planned fields.
- 07 rs-coalescing RED — 7 tests specified; cargo test failed for the new contract (see paired test commit).
- 07 rs-coalescing GREEN — 7 passed; Same-link full snapshot emitted once; unspecified-source RS uses all-nodes multicast; existing earlier response never postponed.
