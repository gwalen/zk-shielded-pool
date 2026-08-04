# Umbrella project for ZK-shielded-pool-related projects

1. [ZK-shielded-pool circuit](https://github.com/gwalen/zk-shielded-pool-circuit) — contains the circuit with tests in Halo2. Based on this circuit, we build the on-chain verifier and off-chain prover.
2. [Solana-verifier](https://github.com/adamsmo/solana-verifier) — on-chain verifier code for ZK-shielded-pool, built by [adamsmo](https://github.com/adamsmo).
3. [ZK-shielded-pool-solana](https://github.com/gwalen/zk-shielded-pool-solana) — contains the Solana program code for ZK-shielded-pool. It handles deposits/withdrawals and calls the verifier.
4. ZK-shielded-pool-client — contains the client code for ZK-shielded-pool. It is a Rust backend server app for interacting with the Solana program: sending deposit/withdrawal transactions and building proofs for the verifier. For educational purposes, it must be run locally with a private key set in an environment variable. In future versions, this will be replaced by a web app with WASM code.
