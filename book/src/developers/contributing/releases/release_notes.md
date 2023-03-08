# Notes

**Prerequisite**: Release notes are generated with [towncrier](https://pypi.org/project/towncrier/). Ensure to have `towncrier` installed and the command is available.

Run `make notes version=<version>` where `<version>` is the version we are generating the release notes for e.g. `0.2.0-alpha`.

Example:

```sh
make notes version=0.2.0-alpha
```

Examine the generated release notes and if needed perform and commit any manual changes.
Generated notes are located in `/docs/release_notes.md`.
