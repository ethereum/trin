# Mac Os

## Prerequisites
- [Rust](https://www.rust-lang.org/) installation
- Xcode Command Line Tools

## Building, Testing, and Running

Note: If you use a VPN, you should disable it before running Trin.

Install Xcode Command Line Tools (MacOS):

```sh
xcode-select --install
```

Add environment variables in current shell session:

```sh
# Optional
export RUST_LOG=<error/warn/info/debug/trace>
export TRIN_DATA_PATH=<path-to-data-directory>
```

Install Rust dependencies (MacOS):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs/ | sh -s -- --default-toolchain stable -y

# Permanently add environment variables to login shell file for reuse across terminal sessions.
if [[ $(echo $SHELL) == "/bin/zsh" ]]; then
  LOGIN_SHELL_FILE=$HOME/.zshrc
elif [[ $(echo $SHELL) == "/bin/bash" ]]; then
  LOGIN_SHELL_FILE=$HOME/.bashrc
else
  echo "The path to the binary of your current shell is: $SHELL"
  echo "Please manually add environment variables to the relevant login shell file" 
  exit 1
fi
echo 'export RUST_LOG=debug' >> $LOGIN_SHELL_FILE
echo 'export PATH="${HOME}/.cargo/bin:${PATH}"' >> $LOGIN_SHELL_FILE
echo 'export RUSTUP_HOME="${HOME}/.rustup"' >> $LOGIN_SHELL_FILE
echo 'export CARGO_HOME="${HOME}/.cargo"' >> $LOGIN_SHELL_FILE
echo 'export TRIN_DATA_PATH="${HOME}/Library/Application Support/trin"' >> $LOGIN_SHELL_FILE
# Source the updated login shell file
. $LOGIN_SHELL_FILE
rustup component add rust-src rustfmt clippy
rustup target add wasm32-unknown-unknown
export RUST_STABLE="2023-08-03"
rustup toolchain install "stable-${RUST_STABLE}" --profile minimal --component rustfmt
rustup default "stable-${RUST_STABLE}"
rustup override set "stable-${RUST_STABLE}"
rustup target add wasm32-unknown-unknown --toolchain "stable-${RUST_STABLE}"
. $HOME/.cargo/env
rustup show
```

You should see something like:
```sh
active toolchain
----------------

stable-2023-08-03-aarch64-apple-darwin (default)
rustc 1.71.1 (eb26296b5 2023-08-03)
```

Build, test, and run:

```sh
cd ~
git clone https://github.com/ethereum/trin.git
cd trin

# Build
cargo build --workspace

# Run test suite
cargo test --workspace

# Build and run test suite for an individual crate
cargo build -p trin-history
cargo test -p trin-history

# Run
cargo run -p trin --release
```

Note: You may also pass environment variable values in the same command as the run command. This is especially useful for setting log levels.

```sh
RUST_LOG=debug cargo run
```

View CLI options:

```sh
cargo run -- --help
```
