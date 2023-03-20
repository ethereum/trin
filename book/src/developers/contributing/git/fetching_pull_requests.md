# Fetching a pull request

We often want or need to run code that someone proposes in a PR. Typically this involves adding the remote of the PR author locally and then fetching their branches.

Example:

```sh
git remote add someone https://github.com/someone/reponame.git
git fetch someone
git checkout someone/branch-name
```

With an increasing number of different contributors this workflow becomes tedious.
Luckily, there's a little trick that greatly improves the workflow as it lets us
pull down any PR without adding another remote.

To do this, we just have to add the following line in the `[remote "origin"]`
section of the `.git/config` file in our local repository.

```sh
fetch = +refs/pull/*/head:refs/remotes/origin/pr/*
```

Then, checking out a PR locally becomes as easy as:

```sh
git fetch origin
git checkout origin/pr/<number>
```

>Replace `origin` ☝ with the actual name (e.g. `upstream`) that we use for the
remote that we want to fetch PRs from.

Notice that fetching PRs this way is *read-only* which means that in case we do
want to contribute back to the PR (and the author has this enabled), we would
still need to add their remote explicitly.
