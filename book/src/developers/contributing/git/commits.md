# Commit messages

## Commit Hygiene

We do not have any stringent requirements on how you commit your work, however
you should work towards the following with your git habits.

## Logical Commits

This means that each commit contains one logical change to the code.  For example:

- commit `A` introduces new API
- commit `B` deprecates or removes the old API being replaced.
- commit `C` modifies the configuration for CI.

This approach is sometimes easier to do *after* all of the code has been
written.  Once things are complete, you can `git reset master` to unstage all
of the changes you've made, and then re-commit them in small chunks using `git
add -p`.

### Commit Messages

We use conventional commits for our commit messages.  This means that your
commit messages should be of the form:

```text
<type>[optional scope]: <description>
```

To learn more about conventional commits please check out the [conventional commits website](https://www.conventionalcommits.org/en/v1.0.0/).

Examples:

- `fix: Update metrics strategy to support multiple subnetworks`
- `refactor(light-client): Refactor light-client crate to use `ethportal-api` consensus types`
- `feat(rpc): Return header to eth_getBlockByHash`

One way to test whether you have it right is to complete the following sentence.

> If you apply this commit it will ________________.
