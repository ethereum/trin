# Deploy trin to network

## First time Setup
- Get access to cluster repo (add person to @trin-deployments)
- Download cluster repo:
```shell=
git clone git@github.com:ethereum/cluster.git
cd cluster
python3 -m venv venv
. venv/bin/activate
pip install ansible
```
- Publish your pgp public key with keybase, using: `keybase pgp select --import`
  - This fails if you don't have a pgp key yet. If so, create one with `gpg --generate-key`
- [Install sops](https://github.com/getsops/sops)
- Contact `@paulj`, get public gpg key into cluster repo
- Make sure your pgp key is working by running:
  ```sops portal-network/trin/ansible/inventories/dev/group_vars/secrets.sops.yml```
- Log in to Docker with: `docker login`
- Ask Nick to be added as collaborator on Docker repo

## Each Deployment

### Prepare
- Announce in Discord #trin that you're about to run the deployment
- Make sure to schedule plenty of time to react to deployment issues

### Update Docker images
Docker images are how Ansible moves the binaries to the nodes. Update the Docker tags with:
```shell=
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
    - [Glados](http://glados.ethportal.net/content/)
    - [Grafana](https://trin-bench.ethdevops.io/d/e23mBdEVk/trin-metrics?orgId=1)
- Go into Portal section of Ansible: `cd portal-network/trin/ansible/`
- Run the deployment: `ansible-playbook playbook.yml --tags trin`
- Wait for completion
- Launch a fresh trin node, check it against the bootnodes
- ssh into a random node and a random bridge node, to check the logs:
	- [find an IP address](https://github.com/ethereum/cluster/blob/master/portal-network/trin/ansible/inventories/dev/inventory.yml)
	- `ssh ubuntu@$IP_ADDR`
  - check logs, ignoring DEBUG: `sudo docker logs trin -n 1000 | grep -v DEBUG`
- Check monitoring tools to see if network health is the same or better as before deployment. Glados might lag for 10-15 minutes, so keep checking back.
- ?? Also release glados, to use the latest trin ??

### Communicate

Notify in Discord chat about the network nodes being updated.

### Update these docs

Immediately after a release is the best time to improve these docs:
- add a line of example code
- fix a typo
- add a warning about a common mistake
- etc.

For more about generally working with mdbook see the guide to [Contribute to
the book](/developers/contributing/book.md).

### Celebrate

Another successful release! 🎉

## FAQ
### What do the Docker tags mean?

- `latest`: [This image](https://github.com/ethereum/trin/blob/master/docker/Dockerfile) with `trin` is built on every push to master
- `latest-bridge`: [This image](https://github.com/ethereum/trin/blob/master/docker/Dockerfile.bridge) with `portal-bridge` is built on every push to master
- `testnet`: This tag is used by Ansible to load `trin` onto the nodes we host
- `bridge`: This tag is used by Ansible to load `portal-bridge` onto the nodes we host

Note that building the Docker image on git's master takes some time. If you merge to master and immediately pull the `latest` Docker image, you won't be getting the build of that latest commit. You have to wait for the Docker build to complete. You should be able to see on github when the Docker build has finished.

### Why can't I decrypt the SOPS file?

You might see this when running ansible, or the sops check:
```shell=
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

### What do I do if Ansible says a node is unreachable?
You might see this during a deployment:
> fatal: [trin-ams3-18]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: ssh: connect to host 178.128.253.26 port 22: Connection timed out", "unreachable": true}

Retry once more. If it times out again, ask `@paulj` to reboot the machine.
