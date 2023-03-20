# Error handling

- Handle errors. Naked `.unwrap()`s aren't allowed, except for in unit tests.
Exceptions must be accompanied by a note justifying usage.
  - In most cases where an exception can be made (E.g., parsing a static value) `.expect()` with a relevant message should be used over a naked unwrap.
- Write descriptive error messages that give context of the problem that occurred. Error messages should be unique, to aid with debugging.
- Meaningful error types should be used in place of `Result< _, String>`.
	- General errors should use the [anyhow](https://docs.rs/anyhow/latest/anyhow/) crate.
	- Custom / typed errors should derive from the `std::error::Error` trait. The [`thiserror`](https://docs.rs/thiserror/1.0.30/thiserror/) crate provides a useful macro to simplify creating custom error types.
