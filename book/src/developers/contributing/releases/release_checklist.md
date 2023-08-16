# Release checklist

## Choosing a version

Make sure that version follows [semver](https://semver.org/) rules e.g (`0.2.0-alpha.3`).

**For the time being, ALWAYS specify the `-alpha` suffix.**

## Bump the version

Update the version number in Cargo.toml file(s), using semantic versioning.
Once that's merged to master, tag it like:

```sh
git tag -a v0.1.0-alpha.6 -m "Version 0.1.0-alpha.6"
git push upstream --tags
```

## Build the binary for release

> ⚠️  **Under development**: This is an untested rough draft. Pair up when
> releasing, to verify.

Build the binary with:

```sh
cargo build --release
```

We no longer use `make release` because it's not worth the effort to release all the dependencies.

> ⚠️  **TODO**: How do we generate binaries for all target systems, for this
> release page? Linux, Mac, Windows, ARM, etc

## Create github release page

Go to [trin tags](https://github.com/ethereum/trin/tags).

Find the tag you pushed, and in the `...` menu, select [Create release]

Write up a high-level overview, and link to the generated release notes.

Attach the generated binaries.

## Deploy

Push these changes out to the nodes we run in the network. See next page for details.
