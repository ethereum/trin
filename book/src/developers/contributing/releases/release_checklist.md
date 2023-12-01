# Release checklist

## First

Ensure that the CI for the latest commit to master is passing.
This ensures that trin itself is working, and that the latest docker image is working and published. 

## Communicate

Announce in #trin chat the upcoming release. Aim for a day or more notice, but
announcing a few minutes before releasing is still better than not saying
anything.

## Choosing a version

Make sure that version follows [semver](https://semver.org/) rules e.g (`0.2.0-alpha.3`).

**For the time being, ALWAYS specify the `-alpha` suffix.**

## Bump the version

- In github, open the page to [create the new release](https://github.com/ethereum/trin/releases/new).
- In the tag, type out the version number that the new release bumps to and select "Create new tag".
- Github should say "Excellent! This tag will be created from the target when you publish this release."
- Click "Generate release notes"
- Select "Set as a pre-release"
- Add "Trin " to the beginning of the release title
- Add any clarifying information that's helpful about the release

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

### Build Instructions
* [Linux](../build_instructions/linux.md)
* [Mac OS](../build_instructions/mac_os.md)
* [Raspberry Pi](../build_instructions/raspberry_pi.md)
* [Windows](../build_instructions/windows.md)

## Deploy

Push these changes out to the nodes we run in the network. See next page for details.

## Communicate

Notify in Discord chat about the new release being complete.

As trin stabilizes, more notifications will be necessary (twitter, blog post, etc). Though we probably want to do at least a small network deployment before publicizing.
