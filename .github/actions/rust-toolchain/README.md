# Rust toolchain composite action

This local composite action installs and configures the Rust toolchain using the runner's preinstalled `rustup`, avoiding external marketplace actions. It sets a minimal profile, installs the requested toolchain, and ensures `rustfmt` and `clippy` are available for formatting and linting.

The scripts in this directory are authored for this repository and do not incorporate third-party licensed content.
