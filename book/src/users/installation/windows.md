# Windows

These are instructions for Native and cross compiling Windows builds 

## Native compilation of Windows

If you don't already have Rust install it
```sh
$ winget install Rustlang.Rustup
```

Install clang/llvm as it is required to compile rocksdb
If you don't already have Rust install it
```sh
$ winget install LLVM.LLVM
```

Add Rust's msvc target
```sh
$ rustup target add x86_64-pc-windows-msvc
```

Install target toolchain
```sh
$ rustup toolchain install stable-x86_64-pc-windows-msvc
```

Build Trin

```sh
$ cargo build -p trin
```


## Cross-compilation for Ubuntu compiling to Windows

This is assuming you already have rust installed on Linux

Install required dependencies
```sh
$ sudo apt update
$ sudo apt upgrade
$ sudo apt install git g++-mingw-w64-x86-64-posix
```

Clone trin and build.
```sh
$ git clone https://github.com/ethereum/trin.git
$ cd trin
$ cargo build -p trin --target x86_64-pc-windows-gnu
```