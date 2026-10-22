# Open Bastion Lab

Provide virtual infrastructure for functional testing of [open-bastion](https://github.com/linagora/open-bastion).

Why not Docker? Because `open-bastion` relies heavily on systemd and we
want to test in a representative environment the generated deployment
artefacts, the real init, a fleet as a fleet (several machines,
per-bastion server groups, `allowed_bastions`) and a portal whose
policy changes.

## Roadmap

* A proxy to [proxmox](https://www.proxmox.com/en/) hypervisor
* More fleets, more tests

## Pre-requisites

* [uv](https://docs.astral.sh/uv/)
* `libvirt`
* A C compiler, `pkg-config` and the `libvirt` and Python 3 development
  files (`libvirt-dev` and `python3-dev` on Debian) to build the
  `libvirt-python` binding

### Libvirt configuration

Make sure the user is in the `libvirt` group and `export
LIBVIRT_DEFAULT_URI=qemu:///system`.

Create a storage pool:

```bash
sudo virsh pool-define-as default dir --target /var/lib/libvirt/images
sudo virsh pool-build default
sudo virsh pool-start default
sudo virsh pool-autostart default
```

Make sure the default NAT network exists:

```bash
sudo virsh net-define /usr/share/libvirt/networks/default.xml 2>/dev/null || true
sudo virsh net-start default 2>/dev/null || true
sudo virsh net-autostart default
```

Edit the default virtual network to make sure it covers the
192.168.122.0/24 range and to add the `<dns>` element for domains to
resolve the LLNG services by name (use `virsh net-edit default`,
followed by `virsh net-destroy default && virsh net-start default`):

```xml
<network>
  <name>default</name>
  <uuid>d503436f-c3ac-437f-b867-9687eda6905d</uuid>
  <forward mode='nat'/>
  <bridge name='virbr0' stp='on' delay='0'/>
  <mac address='52:54:00:ad:b8:ab'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
    </dhcp>
  </ip>
  <dns>
    <host ip='192.168.122.1'>
      <hostname>auth.example.com</hostname>
      <hostname>manager.example.com</hostname>
      <hostname>reload.example.com</hostname>
      <hostname>test1.example.com</hostname>
      <hostname>test2.example.com</hostname>
    </host>
  </dns>
</network>
```

Install the base disk:
```bash
sudo install -d -m 0755 -o root -g root /var/lib/libvirt/images
sudo curl -fL -o /var/lib/libvirt/images/debian-13-generic-amd64.qcow2.part \
  https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2
sudo mv /var/lib/libvirt/images/debian-13-generic-amd64.qcow2.part \
        /var/lib/libvirt/images/debian-13-generic-amd64.qcow2
sudo chown libvirt-qemu:libvirt-qemu /var/lib/libvirt/images/debian-13-generic-amd64.qcow2
sudo chmod 0440 /var/lib/libvirt/images/debian-13-generic-amd64.qcow2
```
No other command should require elevated privileges.

### Build dev packages and serve locally

At the root of a local clone of `open-bastion` Git repository:

```bash
./scripts/build-dev-deb
sudo mkdir -p /srv/ob-lab && sudo chown ${USER}:${USER} /srv/ob-lab
mv ../open-bastion*_0.*.deb /srv/ob-lab/
cd /srv/ob-lab
dpkg-scanpackages -m . /dev/null > Packages && gzip -kf Packages
python3 -m http.server 8000 --directory /srv/ob-lab
```

See [scripts/refresh-lab-packages.sh](./scripts/refresh-lab-packages.sh) for a script that automatize this
under the hypothesis that the `open-bastion` Git repository is a sibling
of the current repository.

💡 In case port 8000 is already used, make sure to update the port in
subsequent commands and configuration files, eg
[examples/inventory](./examples/inventory.yaml).

## Automatic functional tests

All the test material is located in [open_bastion_tests](./open_bastion_tests): scenarios in
`features/`, the tests binding them in `tests/`, the steps implementing
them in `steps/`, and copies of everything they need in `data/`. It relies
on [pytest-bdd](https://pytest-bdd.readthedocs.io/en/stable/).

```bash
uv sync
source .venv/bin/activate
pytest
```

⚠️ The tests take the lab over: they create the fleet, snapshot it, deploy
open-bastion on it and delete it at the end, and they run their own LLNG
container. Free the lab first (`ob-lab delete`, then `docker compose
-f open_bastion_tests/data/llng/docker-compose.yml down -v`) and see
[open_bastion_tests/README.md](./open_bastion_tests/README.md) for what they
need, what they do and what they leave behind.

⏰ Test can be long to execute…

To run a selection of scenarios, forge a command modeled as:

```bash
FEATURE_PATH=open_bastion_tests/tests/test_ansible_playbook_maximum_security.py
SCENARIO=test_bastion_access_removed
pytest "${FEATURE_PATH}::${SCENARIO}"
```

Add `-x` to stop at the first failing test (`--maxfail=N` to stop after N
failures). A failing run leaves the fleet and the portal running for
inspection, and prints at the end the commands that free them; a passing run
frees them itself.

To start a fully configured fleet:

```bash
pytest --log-cli-level="INFO" -m debug
```
Press Ctrl-c to stop the fleet and free all resources.

## Manually testing Open Bastion

What the tests perform automatically by hand.

### Machines

Create the configuration file (adapt to point to an existing SSH public key):

```bash
mkdir -p ~/.config/open-bastion-lab/
cat > ~/.config/open-bastion-lab/config.toml <<EOF
authorized_keys = [
  "$(cat ~/.ssh/id_ed25519.pub)",
]
fleet = "two-backends"
EOF
```

💡 The SSH public keys listed in `authorized_keys` will end up in the
created machines for a service account to be able to connect through
SSH. You may not want to use production keys for that purpose.

Install the package and its dependencies (the package itself is
installed in editable mode):

```bash
uv sync
source .venv/bin/activate
```

The created Python virtual environment has all dependencies installed,
don't forget to enable the environment before `ob-lab` calls (or prefix
with `uv run`).

Then start the default machine fleet with:
```bash
ob-lab start
ob-lab check
```

💡 The start command relies on a temporarily HTTP server listening on
port 8001. It can be changed through the
`~/.config/open-bastion-lab/config.toml` file.

Use `ob-lab stop` to stop the machines and `ob-lab delete` to free all
resources.

Worth noting:
* Each machine (domains in the `libvirt` terminology) has a static IPv4
  address and MAC address derived from its name, `<role>-<count>`:

  | machine   | IPv4            | MAC               |
  |-----------|-----------------|-------------------|
  | bastion-1 | 192.168.122.2   | 52:54:00:12:00:01 |
  | backend-1 | 192.168.122.66  | 52:54:00:12:01:01 |
  | backend-2 | 192.168.122.67  | 52:54:00:12:01:02 |

  `bastion` is role 0, `backend` 1 and `standalone` 2; each role owns a
  block of 64 addresses and the first address of the subnet (`.1`) is left
  to the host. The addresses are served to the guests by `ob-lab` itself,
  when it provisions them.

  The static address is applied by `cloud-init` which fetch its
  configuration through the network; So each domain uses a temporary
  IP obtained by DHCP at early boot until `cloud-init` reconfigures the
  network interface. One can fix the early IPs through the default
  network configuration.

* The server SSH key is generated during the first boot. So it changes
  during the machines lifecycle. Don't forget to cleanup the "known
  hosts" between a `delete` and a `create`:
  ``` bash
  printf '%s\n' 2 66 67 | xargs -i \
       ssh-keygen -f ~/.ssh/known_hosts -R 192.168.122.{}
  ```
* A single account `maintainer` with password `password` is created
* The `maintainer` account can `sudo` to elevate privileges without
  password
* Login through the console is available through `virsh console DOMAIN`
* The SSH service is listening and the keys specified in the
  configuration file allow `maintainer` to connect without password

### LLNG

Make sure `/etc/hosts` contains a line:

```
192.168.122.1 auth.example.com manager.example.com reload.example.com test1.example.com test2.example.com
```

The `open-bastion` Git repository has demos one can use, eg:

```bash
pushd docker-demo-maxsec
docker compose up -d
```

The LLNG provided by these demos have  the required plugins installed
and are fully configured for different scenarios.

For a bare LLNG, one can use
[examples/docker-compose.yml](./examples/docker-compose.yml). Configuration ready to import are
available in [examples/llng](./examples/llng).

### Shell

```bash
ob-builder --config ob-builder-local.yml \
           --output-shell shell

scp shell/bootstrap-local-bastion.sh maintainer@192.168.122.2:/tmp

ssh maintainer@192.168.122.2 'sudo /tmp/bootstrap-local-bastion.sh'
```

Use `-F ./examples/ssh_config` when testing with users `dwho`,
`rtyler`, etc.

### Ansible

Make sure the "known hosts" file is properly populated so user can
connect through SSH to the `maintainer` account without password on any
host in the generated fleet. The machines' keys are generated at their
first boot, so they change with each creation (see [Machines](#machines)):

```bash
printf '%s\n' 2 66 67 | xargs -i \
     ssh-keygen -f ~/.ssh/known_hosts -R 192.168.122.{}
ssh-keyscan 192.168.122.2 192.168.122.66 192.168.122.67 >> ~/.ssh/known_hosts
```

Update the value of the `public_key_file` key in
[examples/ob-builder-local](./examples/ob-builder-local.yml) to the key used in the configuration file.

At the root of the lab repository:

```
mkdir -p ansible; cd ansible
ob-builder --config ../examples/ob-builder-local.yml --output-ansible .
```

Adapt the [examples/inventory.yaml](./examples/inventory.yaml) file to the LLNG configuration (it
makes the assumption of two OIDC RPs `pam-bastion` and `pam-access`). Play
the playbook to install `open-bastion` and its requirements:

```bash
ansible-playbook -i ../examples/inventory.yaml site.yml
```

Then follow the instructions given by each of the following commands
to enroll the fleet:

```bash
ssh -t maintainer@192.168.122.2 \
    'sudo OB_CLIENT_SECRET=pamsecret ob-enroll -g bastion'
ssh -t maintainer@192.168.122.66 \
    'sudo OB_CLIENT_SECRET=pamsecret ob-enroll -g backend'
ssh -t maintainer@192.168.122.67 \
    'sudo OB_CLIENT_SECRET=pamsecret ob-enroll -g backend'
```

Then replay the playbook with the setup step enabled:

```bash
ansible-playbook -i ../examples/inventory.yaml site.yml  -e ob_auto_setup=true
```

Once the play ends, users that own certificates from LLNG CA can
connect:

```bash
$ ssh -F examples/ssh_config dwho@bastion-1
dwho@bastion-1:~$ ob-ssh backend-2
Warning: Permanently added 'backend-2' (ED25519) to the list of known hosts.
dwho@backend-2:~$
```
