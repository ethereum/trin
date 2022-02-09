# Contributor Guidelines

These guidelines are heavily influenced by the [Snake-Charmer Tactical Manual](https://github.com/ethereum/snake-charmers-tactical-manual). While the manual is written with a focus on Python projects, there is tons of relevant information in there for how to effectively contribute to open-source projects, and it's recommended that you look through the manual before contributing.


## Imports

- In `*.rs` files, imports should be split into 3 groups [src](https://github.com/rust-dev-tools/fmt-rfcs/issues/131) and separated by a single line. Within a single group, imported items should be sorted alphabetically.
	- Imports from `'std'`
	- Imports from external crates
	- Imports from within the same crate (`trin-core`, `trin-history`, `trin-state` inclusive).
- Alphabetize imports in `Cargo.toml`


## Logging

- All logging should be done with the `log` library and not `println!()` statements.
- Appropriate log levels (`debug`, `warn`, `info`, etc.) should be used with respect to their content.
- Log statements should be declarative, useful, succinct and formatted for readability.
	- BAD: `Oct 25 23:42:11.079 DEBUG trin_core::portalnet::events: Got discv5 event TalkRequest(TalkRequest { id: RequestId([226, 151, 109, 239, 115, 223, 116, 109]), node_address: NodeAddress { socket_addr: 127.0.0.1:4568, node_id: NodeId { raw: [5, 208, 240, 167, 153, 116, 216, 224, 160, 101, 80, 229, 154, 206, 113, 239, 182, 109, 181, 137, 16, 96, 251, 63, 85, 223, 235, 208, 3, 242, 175, 11] } }, protocol: [115, 116, 97, 116, 101], body: [1, 1, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0], sender: Some(UnboundedSender { chan: Tx { inner: Chan { tx: Tx { block_tail: 0x55c4fe611290, tail_position: 1 }, semaphore: 0, rx_waker: AtomicWaker, tx_count: 2, rx_fields: "..." } } }) })    
`
	- GOOD: `Oct 25 23:43:02.373 DEBUG trin_core::portalnet::overlay: Received Ping(enr_seq=1, radius=18446744073709551615)    
`

## Pull Requests

We are a distributed team.  The primary way we communicate about our code is
through github via pull requests.

* When you start work on something you should have a pull request opened that
  same day.
* Mark unfinished pull requests with the "Work in Progress" label.
* Before submitting a pr for review, you should run the following commands
  locally and make sure they are passing, otherwise CI will raise an error.
  * `cargo fmt --all -- --check` and `cargo clippy --all -- --deny warnings` for linting checks
  * `RUSTFLAGS='-D warnings' cargo test --workspace` to run all tests
  * Run the `ethportal-peertest` harness against a locally running node. Instructions
	can be found in [README](ethportal-peertest/README.md).
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


## Commit Hygiene

We do not have any stringent requirements on how you commit your work, however
you should work towards the following with your git habits.

### Logical Commits

This means that each commit contains one logical change to the code.  For example:

- commit `A` introduces new API
- commit `B` deprecates or removes the old API being replaced.
- commit `C` modifies the configuration for CI.

This approach is sometimes easier to do *after* all of the code has been
written.  Once things are complete, you can `git reset master` to unstage all
of the changes you've made, and then re-commit them in small chunks using `git
add -p`.

### Rebasing

You should be using `git rebase` when there are *upstream* changes that you
need in your branch.  You **should not** use `git merge` to pull in these
changes.


### Commit Messages

We don't care much about commit messages other than that they be sufficiently
descriptive of what is being done in the commit.

The *correct* phrasing of a commit message.

- `fix bug #1234` (correct)
- `fixes bug #1234` (wrong)
- `fixing bug #1234` (wrong)

One way to test whether you have it right is to complete the following sentence.

> If you apply this commit it will ________________.


## Code Review

Every team member is responsible for reviewing code. The designations :speech_balloon:, :heavy_check_mark:, and :x: **should** be left by a reviewer as follows:

- :speech_balloon: (Comment) should be used when there is not yet an opinion on overall validity of complete PR, for example:
  - comments from a partial review
  - comments from a complete review on a Work in Progress PR
  - questions or non-specific concerns, where the answer might trigger an expected change before merging
- :heavy_check_mark: (Approve) should be used when the reviewer would consider it acceptable for the contributor to merge, *after addressing* all the comments. For example:
  - style nitpick comments
  - compliments or highlights of excellent patterns ("addressing" might be in the form of a reply that defines scenarios where the pattern could be used more in the code, or a simple :+1:)
  - a specific concern, where multiple reasonable solutions can adequately resolve the concern
  - a Work in Progress PR that is far enough along
- :x: (Request changes) should be used when the reviewer considers it unacceptable to merge without another review of changes that address the comments. For example:
  - a specific concern, without a satisfactory solution in mind
  - a specific concern with a satisfactory solution provided, but *alternative* solutions **may** be unacceptable
  - any concern with significant subtleties
  
Contributors **should** react to reviews as follows:
- :x: if *any* review is marked as "Request changes":
  - make changes and/or request clarification
  - **should not** merge until reviewer has reviewed again and changed the status
- (none) if there are no reviews, contributor should not merge.
- :speech_balloon: if *all* reviews are comments, then address the comments. Otherwise, treat as if no one has reviewed the PR.
- :heavy_check_mark: if *at least one* review is Approved, contributor **should** do these things before merging:
  - make requested changes
  - if any concern is unclear in any way, ask the reviewer for clarification before merging
  - solve a concern with suggested, or alternative, solution
  - if the reviewer's concern is clearly a misunderstanding, explain and merge. Contributor should be on the lookout for followup clarifications on the closed PR
  - if the contributor simply disagrees with the concern, it would be best to communicate with the reviewer before merging
  - if the PR is approved as a work-in-progress: consider reducing the scope of the PR to roughly the current state, and merging. (multiple smaller PRs is better than one big one)

It is also recommended to use the emoji responses to signal agreement or that
you've seen a comment and will address it rather than replying.  This reduces
github inbox spam.

Everyone is free to review any pull request.

Recommended Reading:

 - [How to Do Code Reviews Like a Human](https://mtlynch.io/human-code-reviews-1/)


## Merging

Once your pull request has been *Approved* it may be merged at your discretion.  In most cases responsibility for merging is left to the person who opened the pull request, however for simple pull requests it is fine for anyone to merge.

If substantive changes are made **after** the pull request has been marked *Approved* you should ask for an additional round of review.

### Fetch Pull Requests without manually adding remotes

We often want or need to run code that someone proposes in a PR. Typically this involves adding the remote of the PR author locally and then fetching their branches.

Example:

```
git remote add someone https://github.com/someone/reponame.git
git fetch someone
git checkout someone/branch-name
```

With an increasing number of different contributors this workflow becomes tedious.
Luckily, there's a little trick that greatly improves the workflow as it lets us
pull down any PR without adding another remote.

To do this, we just have to add the following line in the `[remote "origin"]`
section of the `.git/config` file in our local repository.

```
fetch = +refs/pull/*/head:refs/remotes/origin/pr/*
```

Then, checking out a PR locally becomes as easy as:

```
git fetch origin
git checkout origin/pr/<number>
```

>Replace `origin` ☝ with the actual name (e.g. `upstream`) that we use for the
remote that we want to fetch PRs from.

Notice that fetching PRs this way is *read-only* which means that in case we do
want to contribute back to the PR (and the author has this enabled), we would
still need to add their remote explicitly.


## Releases
- When cutting a new release, the versions of every crate in this repo should be updated simultaneously to the new version. 

### Versioning

Make sure that version follows [semver](https://semver.org/) rules e.g (`0.2.0-alpha`).

**For the time being, ALWAYS specify the `-alpha` suffix.**

### Generate Release Notes

**Prerequisite**: Release notes are generated with [towncrier](https://pypi.org/project/towncrier/). Ensure to have `towncrier` installed and the command is available.

Run `make notes version=<version>` where `<version>` is the version we are generating the release notes for e.g. `0.2.0-alpha`.

Example:

```
make notes version=0.2.0-alpha
```

Examine the generated release notes and if needed perform and commit any manual changes.

### Generate the release

**Prerequisite**: Make sure the central repository is configured as `origin`.

Run `make release version=<version>`.

Example:

```
make release version=0.2.0-alpha
```

### Update testnet nodes
Run `make create-docker-image` and `make push-docker-image` commands with the appropriate version.

Example:

```
make create-docker-image version=0.2.0-alpha
make push-docker-image version=0.2.0-alpha
```

Run the Ansible playbook to fetch the newly available docker image and update the testnet nodes.

## Tests

Testing is essential to the production of software with minimal flaws. The default should always be writing tests for the code you produce.

Testing also introduces overhead into our workflow. If a test suite takes a long time to run, it slows down our iteration cycle. This means finding a pragmatic balance between thorough testing, and the speed of our test suite, as well as always iterating on our testing infrastructure.


## Comments

Any datatype of significance **should** have an accompanying comment briefly describing its role and responsibilities. Comments are an extremely valuable tool in open-source projects with many different contributors, and can greatly improve development speed. Explain your assumptions clearly so others don't need to dig through the code.
- Rust [doc comments](https://doc.rust-lang.org/rust-by-example/meta/doc.html) are the most best way to comment your code.


## Error handling
- Handle errors, avoid naked `.unwrap()`s, except for in unit tests. Write descriptive error messages that give context of the problem that occured.
- Meaningful error types should be used in place of `Result< _, String>`.
	- General errors should use the [anyhow](https://docs.rs/anyhow/latest/anyhow/) crate.
	- Custom / typed errors should derive from the `std::error::Error` trait. The [`thiserror`](https://docs.rs/thiserror/1.0.30/thiserror/) crate provides a useful macro to simplify creating custom error types.


## Code Style
- Minimize the amount of `.clone()`s used. Cloning can be a useful mechanism, but should be used with discretion. When leaned upon excessively to [satisfy the borrow checker](https://rust-unofficial.github.io/patterns/anti_patterns/borrow_clone.html) it can lead to unintended consequences.
