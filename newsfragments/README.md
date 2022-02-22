This directory collects "newsfragments": short files that each contain
a snippet of markdown-formatted text that will be added to the next
release notes. This should be a description of aspects of the change
(if any) that are relevant to users. (This contrasts with the
commit message and PR description, which are a description of the change as
relevant to people working on the code itself.)

Each file should be named like `<ISSUE>.<TYPE>.md`, where
`<ISSUE>` is an issue numbers, and `<TYPE>` is one of:

* `added` - For new features.
* `changed` - For changes in existing functionality.
* `deprecated` - For soon-to-be removed features.
* `removed` - For now removed features.
* `fixed` - For any bug fixes.
* `security` - In case of vulnerabilities.
* `internal` - Internal changes - for Trin contributors.
* `doc` - Improved documentation.

So for example: `123.added.md`, `456.fixed.md`

If the PR fixes an issue, use that number here. If there is no issue,
then open up the PR first and use the PR number for the newsfragment.

Note that the `towncrier` tool will automatically
reflow your text, so don't try to do any fancy formatting. Run
 `towncrier --draft` to get a preview of what the release notes entry
 will look like in the final release notes.
