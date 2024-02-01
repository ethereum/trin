# Submodules

This project uses [Git Submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules). If you
just cloned the project, be sure to run:

```console
$ git submodule update --init
```

This page provides short overview of most common use cases.

## Pulling in Upstream Changes from the Submodule Remote

You want to do this when the remote version of submodule is updated. The simplest way to resolve
this is to run:

```console
$ git submodule update --remote --rebase
```

> If you modified your local submodule, you might want to use different flags.

If you run `git status`, you should see that submodule is updated. Commit and push the changes so
others can use the same version.

## Pulling Upstream Changes from the Project Remote

If somebody else updated the submodule and you pulled the changes, you have to update your local
clone as well. The message `"Submodules changed but not updated"` will show when running
`git status`. To update local submodule, run:

```console
$ git submodule update --init
```
