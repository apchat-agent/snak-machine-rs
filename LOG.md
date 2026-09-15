# Task 2 TDD log

Test counts are named Rust tests (table rows are additional assertions). RED compile errors are intentional missing APIs, never unrelated syntax failures. Full cargo output is retained locally in `.lane/tdd/`. The initial RED includes only its test and Cargo test-runner metadata; production source begins in GREEN. Pcap will be an optional feature per task 2, overriding the plan's default-backend build choice, using the planned dynamic loader and exact dependency pins.

- 01 envelope RED — 1 test; missing library/envelope API, cargo test failed as intended.
- 01 envelope GREEN — 1 passed; checked borrowed envelopes, Ethernet padding and payload bounds; no router state yet.
