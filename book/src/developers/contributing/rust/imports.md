# Imports

- In `*.rs` files, imports should be split into 3 groups [src](https://github.com/rust-dev-tools/fmt-rfcs/issues/131) and separated by a single line. Within a single group, imported items should be sorted alphabetically.
	- Imports from `'std'`
	- Imports from external crates
	- Imports from within the same crate (`trin-core`, `trin-history`, `trin-state` inclusive).
- Alphabetize imports in `Cargo.toml`
