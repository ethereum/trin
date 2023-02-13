# Style

## Clone

Minimize the amount of `.clone()`s used. Cloning can be a useful mechanism, but should be used with discretion. When leaned upon excessively to [satisfy the borrow checker](https://rust-unofficial.github.io/patterns/anti_patterns/borrow_clone.html) it can lead to unintended consequences.

## String interpolation

Use interpolated string formatting when possible.
- Do `format!("words: {var:?}")` not `format!("words: {:?}", var)`