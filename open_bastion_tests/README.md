# open-bastion-tests

Functional tests of [open-bastion](https://github.com/linagora/open-bastion) against the infrastructure
[open-bastion-lab](../README.md) answers to the question: does the deployment flow
actually produce a working fleet?.

It's not a substitute for the docker based suite coming with
`open-bastion` sources.

The organisation is [pytest-bdd](https://pytest-bdd.readthedocs.io/en/stable/) scenarios in [features](./features), the tests
binding them in [tests](./tests), the steps implementing them in [steps](./steps), and
copies of everything they need in [data](./data).

## Running them

```bash
uv sync
source .venv/bin/activate
pytest
```

On top of what the lab needs ([Pre-requisites](../README.md#pre-requisites)):

* `ob-builder`, from the `open-bastion-builder` package, and
  `ansible-playbook` in the `PATH`;
* Docker, with the `yadd/lemonldap-ng-full:exp` image pulled: the portal runs
  in its own compose project;
* the `/etc/hosts` line the portal answers to, since `ob-builder` reads the SSO
  metadata, the SSH CA key and the revocation list from it by name:

  ```
  192.168.122.1 auth.example.com manager.example.com reload.example.com test1.example.com test2.example.com
  ```

The tests take the lab over, so the environment has to be free:

* the fleet must not exist, free it with `ob-lab delete`;
* the `open-bastion-tests` compose project must not be running, clean it up
  with `docker compose -f open_bastion_tests/data/llng/docker-compose.yml
  down -v`;
* port 80 of the host serves the LLNG container of the tests, so stop any
  other portal;
* the package server of the lab
  ([Build dev packages and serve locally](../README.md#build-dev-packages-and-serve-locally))
  must be up.

They bring their own SSH key: `id_ob_tests_maintainer` is generated in their
working directory and deployed to the `maintainer` account of the machines,
so nothing here depends on the keys of whoever runs them. The
`authorized_keys` of the lab configuration are deployed as well, to be able
to look at the machines during a run.

## What a run does

Creating the fleet, deploying open-bastion on it and enrolling it take
minutes, so a fleet is created once, restored at the start of each feature,
and what a feature builds or deploys is kept for its scenarios:

|Scope   |Fixture                                            |Work                                                                                               |
|--------|---------------------------------------------------|---------------------------------------------------------------------------------------------------|
|session |`maintainer_key`, `labs`, `llng`                   |generate the key, create the machines of each fleet a feature asks for, wait for `cloud-init`, snapshot them, delete them at the end; run the portal|
|feature |`module_dir`, `administrator`, `deployment`        |restore the fleet, import the LLNG configuration, build the artefact, play it or run the installers|
|scenario|`fleet`, `playbook`, `user_factory`, `user_ssh_config`, `scenario_dir`|name the machines and the configuration, sign a key, open a session, keep what was tried|

A feature says what it runs — which fleet, which portal configuration, which
ob-builder artefact — in its own text, and its steps do it: `fleet` and
`playbook` are what the first steps of a Background give the ones after
them, not fixtures a module declares.

Bringing the fleet up and reverting it are `ob-lab snapshot` and `ob-lab
restore` on the command line too.

## What a run leaves behind

Everything a feature builds, and everything a scenario produces (SSH keys,
certificates, portal answers, connection attempts), is written to a temporary
working directory whose path is printed in the header of the run. That
directory is **removed when the run passes and kept when it fails**:

```
/tmp/ob-lab-tests-3n8x1k2p/
  id_ob_tests_maintainer             key pair of the maintainer account
  test_ansible_playbook_maximum_security/   one directory per feature
    ob-builder-max-security.yml      configuration handed to ob-builder
    ob-builder.log
    inventory-for-three-backends.yml inventory handed to ansible-playbook
    ansible/site.yml                 generated playbook
    ansible-playbook.log
    test_bastion_access-dwho-success/
      ssh_config                     the copy, pointing at the keys below
      llng/sign-dwho.json            answer of the portal to /ssh/sign
      ssh/.ssh/id_dwho               key pair, and its certificate next to it
      ssh/connect-bastion-1.log
```

A failing run leaves the fleet and the portal running, so the state
the failure came from can be inspected. A passing run frees the lab
itself.

## Reading what the deployment left

A configured fleet hands elevation to the portal: once `ob-bastion-setup` has
run, no local account can `sudo` any more, the `maintainer` one included.
A check that has to read a root-owned file — the sshd drop-in serving the
service-account keys, the sudo stack of the bastion, the bastions a backend
accepts — therefore cannot go through SSH. It asks the QEMU guest agent of
the machine instead: the agent answers on its virtio channel, before PAM and
sshd, and runs as root.

`open_bastion_tests/support/guest_agent.py` wraps it (`run`, `shell`,
`read_text`, `exists`), and `Fleet.run_as_root` / `Fleet.read_as_root` do the
same through a machine of the fleet. The scenarios using them are at the end
of `features/ansible_playbook_maximum_security.feature`.

The agent takes a few seconds after a guest boots to connect; the fleet kept
from a failed run can be read the same way:

```bash
python -c "
from open_bastion_tests.support import guest_agent as ga
print(ga.read_text('bastion-1', '/etc/pam.d/sudo'))"
```

The base image has to keep `qemu-guest-agent` enabled for this to work.

## Writing a scenario

🚧
