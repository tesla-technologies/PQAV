# Contributing

We welcome contributions! Please follow these steps to contribute to the PQAV project:

1. Open an issue first to discuss the proposed changes.
2. Fork the repository and create a new branch for your work.
3. Before opening a Pull Request, you **must** ensure your code passes the CI requirements locally:
   - Run `cargo fmt --all` (Code formatting)
   - Run `cargo clippy -- -D warnings` (Linter, no warnings allowed)
   - Run `cargo test` (All tests must pass)
4. Open a Pull Request describing your changes.
