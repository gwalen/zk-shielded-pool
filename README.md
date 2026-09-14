# Umbrella project for ZK-shielded-pool-related projects

An experimental shielded SOL pool on Solana built with Zero-knowledge proof verification. It is designed to let users deposit SOL and later withdraw it without revealing which deposit they are spending. A zero-knowledge proof checks that the user knows the deposit secret and that the withdrawal matches the amounts and destinations chosen when making the deposit.

Each deposit supports up to three different destination addresses and three withdrawal amounts, called chunks. The chunks must add up to the deposited amount, but users can choose to withdraw only some of them. For example, a 9 SOL deposit could contain chunks of 4 SOL, 4.999 SOL, and 0.001 SOL. The user could withdraw the first two and leave the small third chunk in the pool. Splitting withdrawals across addresses and leaving dust can make simple amount matching harder, although amounts and timing can still reveal connections. 

## Tech stack

- Anchor v2 (no_std Rust)
- Halo2 circuits

This program uses **Anchor v2** and **`no_std` Rust**, which runs without Rust's standard library. 
Proofs are generated off chain and checked by a separate on-chain verifier, so the full Halo2 proving library does not need to run on Solana.

| Metric | Value |
| --- | --- |
| On-chain verification | 816,983 CU |
| Proof size | 1,088 bytes |
| Public inputs | 5 × 32 bytes (160 bytes) |

The pool and verifier use Solana's built-in cryptographic operations through [syscalls](https://solana.com/docs/core/programs/syscall-reference), which are calls from the program into the validator runtime. This reduces CU usage by moving expensive cryptographic work out of the program's Rust execution.

| Syscall | Used for |
| --- | --- |
| `sol_poseidon` | Hashes deposit commitments, Merkle tree nodes, and recipient addresses in the pool program. |
| `sol_keccak256` | Checks the uploaded proof's hash and derives the verifier's challenge values from the proof and public inputs. |
| `sol_alt_bn128_group_op` | Adds and multiplies BN254 curve points to combine proof commitments, then performs the final pairing check that validates the proof. |
| `sol_alt_bn128_compression` | Expands the proof's compressed BN254 G1 points from 32 bytes into 64-byte coordinates for verification. |
| `sol_big_mod_exp` | Computes the field inverses needed for division in the verifier, using modular exponentiation. |

The 816,983 CU figure above is for the complete proof-verification run, not a measurement of the savings from each syscall. The table lists the cryptographic calls used by the current pool and verifier, excluding routine framework calls for account handling and logging.

## Notes:

This differs from Tornado Cash Classic, which uses fixed deposit and withdrawal amounts, including 0.1, 1, 10, and 100 ETH pools. This project's circuits use **Halo2 in Rust**, while Tornado Cash Classic uses [Circom](https://docs.tornado.cash/tornado-cash-classic/circuits). Rust was used here. 
Inspected proof scheme: prover done with : BN254/KZG/GWC, tornado classic was using Groth16 over BN254.

**The project is under active development, and may contain bugs.**

## Sub-projects

List of all sub-projects that together make up this ZK-shielded-pool project.

1. [ZK-shielded-pool circuit](https://github.com/gwalen/zk-shielded-pool-circuit) — contains the circuit with tests in Halo2. Based on this circuit, we build the on-chain verifier and off-chain prover.
2. [Solana-verifier](https://github.com/adamsmo/solana-proof-generator) — on-chain verifier code for ZK-shielded-pool, built by [adamsmo](https://github.com/adamsmo).
3. [ZK-shielded-pool-solana](https://github.com/gwalen/zk-shielded-pool-solana) — contains the Solana program code for ZK-shielded-pool. It handles deposits/withdrawals and calls the verifier.
4. ZK-shielded-pool-client — contains the client code for ZK-shielded-pool. It is a Rust backend server app for interacting with the Solana program: sending deposit/withdrawal transactions and building proofs for the verifier. For educational purposes, it must be run locally with a private key set in an environment variable. In future versions, this will be replaced by a web app with WASM code.
