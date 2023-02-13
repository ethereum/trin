# Generation

## Crate versions

When cutting a new release, the versions of every crate in this repo should be updated simultaneously to the new version.

## Generate the release

**Prerequisite**: Make sure the central repository is configured as `origin`.

Run `make release version=<version>`.

Example:

```sh
make release version=0.2.0-alpha
```

### Update testnet nodes
Run `make create-docker-image` and `make push-docker-image` commands with the appropriate version.

Example:

```sh
make create-docker-image version=0.2.0-alpha
make push-docker-image version=0.2.0-alpha
```

Run the Ansible playbook to fetch the newly available docker image and update the testnet nodes.
