# Deployment

## Update testnet node images
Run `make create-docker-image` and `make push-docker-image` commands with the appropriate version.

Example:

```sh
make create-docker-image version=0.2.0-alpha.3
make push-docker-image version=0.2.0-alpha.3
```

## Deploy testnet nodes

Run the Ansible playbook to fetch the newly available docker image and update the testnet nodes.

## Communicate

Notify in Discord chat about the new release being complete, and the network nodes being updated.

As trin stabilizes, more notifications will be necessary (twitter, blog post, etc).

## Update these docs

Immediately after a release is the best time to improve these docs:
- add a line of example code
- fix a typo
- add a warning about a common mistake
- etc.

The source for this section is at `book/src/developers/contributing/releases/`.
For more about generally working with mdbook see the guide to [Contribute to
our book](/developers/contributing/book.md).

## Celebrate

Another successful release! 🎉
