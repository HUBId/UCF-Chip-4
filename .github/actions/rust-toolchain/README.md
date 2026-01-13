# Rust toolchain composite action

This local composite action configures the stable Rust toolchain using the runner's preinstalled `rustup`, avoiding external marketplace actions. It sets the default toolchain (configurable via inputs) and ensures `rustfmt` and `clippy` are available for formatting and linting.

The scripts in this directory are authored for this repository and do not incorporate third-party licensed content.
