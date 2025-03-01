# Deploy trin to network

## First time Setup
- Get access to cluster repo (add person to @trin-deployments)
- `git clone` the cluster repo: https://github.com/ethereum/cluster.git
- Install dependencies within `cluster` virtualenv:
    ```bash
    cd cluster
    python3 -m venv venv
    . venv/bin/activate
    pip install ansible
    pip install docker
    sudo apt install ansible-core
    ```
    On mac you can do `brew install ansible` instead of `apt`.

- [Install keybase](https://keybase.io/docs/the_app/install_linux)
- Publish your pgp public key with keybase, using: `keybase pgp select --import`
  - This fails if you don't have a pgp key yet. If so, create one with `gpg --generate-key`
- [Install sops](https://github.com/getsops/sops)
- Contact `@paulj`, get public pgp key into cluster repo
- Contact `@paulj`, get public ssh key onto cluster nodes

- Make sure your pgp key is working by running:
  ```sops portal-network/trin/ansible/inventories/dev/group_vars/secrets.sops.yml```
- Log in to Docker with: `docker login`
- Ask Nick to be added as collaborator on Docker repo

- Needed for [rebooting nodes](#what-do-i-do-if-ansible-says-a-node-is-unreachable)
    - [Install doctl](https://docs.digitalocean.com/reference/doctl/how-to/install/)
    - Contact `@paulj` to get `doctl` API key
    - Make sure API key works by running: `doctl auth init`

## Each Deployment

### Prepare
- Generally we want to cut a new release before deployment, see previous page for instructions.
- Announce in Discord #trin that you're about to run the deployment
- Make sure to schedule plenty of time to react to deployment issues

### Update Docker images
Docker images are how Ansible moves the binaries to the nodes. Update the Docker tags with:
```shell
docker pull portalnetwork/trin:latest
docker pull portalnetwork/trin:latest-bridge
docker image tag portalnetwork/trin:latest portalnetwork/trin:testnet
docker image tag portalnetwork/trin:latest-bridge portalnetwork/trin:bridge
docker push portalnetwork/trin:testnet
docker push portalnetwork/trin:bridge
```

This step directs Ansible to use the current master version of trin. Read [about the tags](#what-do-the-docker-tags-mean) to understand more.

### Run ansible
- Check monitoring tools to understand network health, and compare against post-deployment, eg~
    - [Glados](https://glados.ethdevops.io/)
    - [Grafana](https://trin-bench.ethdevops.io/d/e23mBdEVk/trin-metrics?orgId=1)
- Activate the virtual environment in the cluster repo: `. venv/bin/activate`
- Make sure you've pulled the latest master branch of the deployment scripts, to include any recent changes: `git pull origin master`
- Go into the Portal section of Ansible: `cd portal-network/trin/ansible/`
- Run the deployment:
    - Trin nodes:
        - `ansible-playbook playbook.yml --tags trin`
    <!-- - State network nodes (check with the team if there is a reason not to update them):
            - `ansible-playbook playbook.yml --tags state-network` -->
- Run Glados deployment: updates glados + portal client (currently configured as trin, but this could change)
    - `cd ../../glados/ansible`
    - `ansible-playbook playbook.yml --tags glados`
- if you experience "couldn't resolve module/action 'community.docker.docker_compose_v2'" error, you might need to re-install the community.docker collection:
    - `ansible-galaxy collection install community.docker --force`
- Wait for completion
- Launch a fresh trin node, check it against the bootnodes
- ssh into random nodes, one of each kind, to check the logs:
    - [find an IP address](https://github.com/ethereum/cluster/blob/master/portal-network/trin/ansible/inventories/dev/inventory.yml)
    - node types
        - bootnode: `trin-*-1`
        - bridge node: `trin-*-2`
        - backfill node: `trin-*-3`
        - regular nodes: all remaining ips
    - `ssh ubuntu@$IP_ADDR`
    - check logs, ignoring DEBUG: `sudo docker logs trin -n 1000 | grep -v DEBUG`
    - for glados logins, use `ssh devops@$IP_ADDR` instead
- Check monitoring tools to see if network health is the same or better as before deployment. Glados might lag for 10-15 minutes, so keep checking back.

### Communicate

Notify in Discord chat about the network nodes being updated.

### Update these docs

Immediately after a release is the best time to improve these docs:
- add a line of example code
- fix a typo
- add a warning about a common mistake
- etc.

For more about generally working with mdbook see the guide to [Contribute to the book](/developers/contributing/book.md).

### Celebrate

Another successful release! 🎉

## FAQ
### What do the Docker tags mean?

- `latest`: [This image](https://github.com/ethereum/trin/blob/master/docker/Dockerfile) with `trin` is built on every push to master
- `latest-bridge`: [This image](https://github.com/ethereum/trin/blob/master/docker/Dockerfile.bridge) with `portal-bridge` is built on every push to master
- `angelfood`: This tag is used by Ansible to load `trin` onto the nodes we host
- `bridge`: This tag is used by Ansible to load `portal-bridge` onto the nodes we host

Note that building the Docker image on git's master takes some time. If you merge to master and immediately pull the `latest` Docker image, you won't be getting the build of that latest commit. You have to wait for the Docker build to complete. You should be able to see on github when the Docker build has finished.

### Why can't I decrypt the SOPS file?

You might see this when running ansible, or the sops check:
```shell
Failed to get the data key required to decrypt the SOPS file.

Group 0: FAILED
  32F602D86B61912D7367607E6D285A1D2652C16B: FAILED
    - | could not decrypt data key with PGP key:
      | github.com/ProtonMail/go-crypto/openpgp error: Could not
      | load secring: open ~/.gnupg/secring.gpg: no such
      | file or directory; GPG binary error: exit status 2

  81550B6FE9BC474CA9FA7347E07CEA3BE5D5AB60: FAILED
    - | could not decrypt data key with PGP key:
      | github.com/ProtonMail/go-crypto/openpgp error: Could not
      | load secring: open ~/.gnupg/secring.gpg: no such
      | file or directory; GPG binary error: exit status 2

Recovery failed because no master key was able to decrypt the file. In
order for SOPS to recover the file, at least one key has to be successful,
but none were.
```
It means your key isn't working. Check with `@paulj`.

If using `gpg` and decryption problems persist, see [this potential fix](https://github.com/getsops/sops/issues/304#issuecomment-377195341).

### What do I do if Ansible says a node is unreachable?

You might see this during a deployment:

> fatal: [trin-ams3-1]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: ssh: connect to host XXX.XXX.XXX.XXX port XX: Connection timed out", "unreachable": true}

Retry once more. If it times out again, run [reboot script](https://github.com/ethereum/cluster/blob/master/portal-network/trin/ansible/reboot_node.sh) (check [First time Setup](#first-time-setup) chapter for setup):

```shell
./reboot_node.sh <host name1>,<host name2>,...,<host nameN>
```

### What if everything breaks and I need to rollback the deployment?
If you observe things breaking or (significantly) degraded network performance after a deployment, you might want to rollback the changes to a previously working version until the breaking change can be identified and fixed. Keep in mind that you might want to rollback just the bridge nodes, or the backfill nodes, as opposed to every node on the network.

1. Go to the commit from the previously released version tag. Click into the CI workflows for that commit and look for the `docker-publish` or `docker-publish-bridge` flow, depending on what images you want to rollback.
2. In the logs for these flows, find the sha256 digest from the `Publish docker image to Docker Hub` step.
3. Pull this specific image locally, using `docker pull portalnetwork/trin@sha256:<HASH>`
4. Retag the target image to this version, for example, if you want to re-deploy the bridges, do: `docker image tag portalnetwork/trin@sha256:6dc0577a2121b711ae0e43cd387df54c8f69c8671abafb9f83df23ae750b9f14 portalnetwork/trin:bridge`
5. Push the newly tagged `bridge` image to Docker Hub. eg. `docker push portalnetwork/trin:bridge`
6. Re-run the ansible script, which will use the newly updated image. Use the `--limit` cli flag if you only want to redeploy a subset of nodes. eg: `ansible-playbook playbook.yml --tags trin --limit backfill_nodes`.
7. Verify that the network is back to regular operation.
