# Pre-release Checklist

Before running a release, follow these steps.

## Communicate

At least one day before the release, announce in chat that you'll be running it.

There may be an emergency scenario that requires a shorter time frame, but at
least one other person on the team should agree with you.

## Update dependencies

- Use `cargo outdated` (and maybe `cargo outdated --aggressive`) to identify any old dependencies.
- Post a PR updating any old dependencies
- If *only* the Cargo.lock changes, then you can merge without a review, after CI turns green.

## Run portal-hive

New releases should not cause regressions in portal-hive. Run it locally
against master and compare it against the [daily portal-hive
results](https://portal-hive.ethdevops.io/).

If there is a regression, pause the release, and announce it in chat. Fixing
the regression is the new priority.

## Generate release notes

**Prerequisite**: Release notes are generated with
[towncrier](https://pypi.org/project/towncrier/). Ensure to have `towncrier`
installed and the command is available.

Run `make notes version=<version>` where `<version>` is the version we are
generating the release notes for e.g. `0.2.0-alpha.3`.

Example:

```sh
make notes version=0.2.0-alpha.3
```

Examine the generated release notes and if needed perform and commit any manual changes.
Generated notes are located in `/docs/release_notes.md`.

Update the release notes using the normal PR process: post it, get a review & merge.
