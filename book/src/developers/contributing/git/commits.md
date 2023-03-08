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

## Commit Messages

We don't care much about commit messages other than that they be sufficiently
descriptive of what is being done in the commit.

The *correct* phrasing of a commit message.

- `fix bug #1234` (correct)
- `fixes bug #1234` (wrong)
- `fixing bug #1234` (wrong)

One way to test whether you have it right is to complete the following sentence.

> If you apply this commit it will ________________.
