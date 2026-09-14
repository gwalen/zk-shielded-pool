# Umbrella project for ZK-shielded-pool-related projects

A Solana privacy pool that lets users **deposit SOL and withdraw it anonymously**, powered by **zero-knowledge (ZK) proofs**.

Each deposit supports up to three different destination addresses and three withdrawal amounts, called chunks. The chunks must add up to the deposited amount, but users can choose to withdraw only some of them. For example, a 9 SOL deposit could contain chunks of 4 SOL, 4.999 SOL, and 0.001 SOL. The user could withdraw the first two and leave the small third chunk in the pool. Splitting withdrawals across addresses and leaving dust are making simple amount matching impossible even with small volume. 

- **Anchor v2** with `no_std` Rust for the Solana program.
- **Halo2** for circuits written in Rust.
- **BN254/KZG/GWC** for proofs: the BN254 curve, KZG polynomial commitments, and the GWC scheme for openings.

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

**The project is under active development, and may contain bugs.**

## Sub-projects

List of all sub-projects that together make up this ZK-shielded-pool project.

1. [ZK-shielded-pool-solana](https://github.com/gwalen/zk-shielded-pool-solana) — contains the Solana program code for ZK-shielded-pool. It handles deposits/withdrawals and calls the verifier.
2. [ZK-shielded-pool circuit](https://github.com/gwalen/zk-shielded-pool-circuit) — contains the circuit with tests in Halo2. Based on this circuit, we build the on-chain verifier and off-chain prover.
3. [Solana-verifier](https://github.com/adamsmo/solana-proof-generator) — on-chain verifier code for ZK-shielded-pool, built by [adamsmo](https://github.com/adamsmo).
4. ZK-shielded-pool-client — contains the client code for ZK-shielded-pool. It is a Rust backend server app for interacting with the Solana program: sending deposit/withdrawal transactions and building proofs for the verifier. For educational purposes, it must be run locally with a private key set in an environment variable. In future versions, this will be replaced by a web app with WASM code.
