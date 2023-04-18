# Pull requests


We are a distributed team.  The primary way we communicate about our code is
through github via pull requests.

* When you start work on something you should have a pull request opened that
  same day.
* Mark unfinished pull requests with the "Work in Progress" label.
* Before submitting a pr for review, you should run the following commands
  locally and make sure they are passing, otherwise CI will raise an error.
  * `cargo fmt --all -- --check` and `cargo clippy --all -- --deny warnings` for linting checks
  * `RUSTFLAGS='-D warnings' cargo test --workspace` to run all tests
* Pull requests **should** always be reviewed by another member of the team
  prior to being merged.
    * Obvious exceptions include very small pull requests.
    * Less obvious examples include things like time-sensitive fixes.
* You should not expect feedback on a pull request which is not passing CI.
    * Obvious exceptions include soliciting high-level feedback on your approach.


Large pull requests (above 200-400 lines of code changed) cannot be effectively
reviewed.  If your pull request exceeds this threshold you **should** make
every effort to divide it into smaller pieces.

You as the person opening the pull request should assign a reviewer.

