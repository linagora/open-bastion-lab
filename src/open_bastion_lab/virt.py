"""Libvirt based implementation of the machine protocol."""

from pathlib import Path
from typing import overload, override, Any, Coroutine, Sequence
import asyncio
import logging
import xml.etree.ElementTree as ET

import libvirt

from open_bastion_lab.config import Config
from open_bastion_lab.machine import HypervisorProxy, Machine, MachineState
from open_bastion_lab.model import Role

LOGGER = logging.getLogger(__name__)

BASE_DISK_FILENAME = "debian-13-generic-amd64.qcow2"

DISK_VIRTUAL_SIZE_GIB = 4

STORAGE_POOL_PATH = "/var/lib/libvirt/images"

# Number of seconds a domain is given to stop on its own
SHUTDOWN_TRIES = 120

type Domains = dict[Role, list[str]]


def _libvirt_error_handler(
    logger: logging.Logger,
    error: tuple[int, int, str, int, str, str | None, str | None, int, int] | list[Any],
) -> None:
    code, domain, message, level, *_ = error
    logger.debug(
        "libvirt error code=%s domain=%s level=%s: %s",
        code,
        domain,
        level,
        message,
    )


libvirt.registerErrorHandler(_libvirt_error_handler, LOGGER.getChild("libvirt"))


def _initialize_connection() -> libvirt.virConnect:
    try:
        conn = libvirt.open(None)
    except libvirt.libvirtError as e:
        raise RuntimeError("Failed to open connection to the hypervisor") from e
    return conn


_STATE_MAPPING: dict[int, MachineState] = {
    libvirt.VIR_DOMAIN_NOSTATE: MachineState.UNKNOWN,
    libvirt.VIR_DOMAIN_RUNNING: MachineState.STARTED,
    libvirt.VIR_DOMAIN_SHUTDOWN: MachineState.STOPPED,
    libvirt.VIR_DOMAIN_SHUTOFF: MachineState.STOPPED,
    libvirt.VIR_DOMAIN_CRASHED: MachineState.STOPPED,
}
# Unsupported states: libvirt.VIR_DOMAIN_BLOCKED
# libvirt.VIR_DOMAIN_PAUSED libvirt.VIR_DOMAIN_PMSUSPENDED


class UnsupportedDomainState(Exception):
    pass


def _convert_libvirt_state(raw: int) -> MachineState:
    try:
        return _STATE_MAPPING[raw]
    except KeyError:
        LOGGER.debug("Unsupported domain state %s", raw)
        raise UnsupportedDomainState(raw)


def _disk_source(xml: str) -> Path | None:
    """Path of the file backed disk found in a domain description."""
    root = ET.fromstring(xml)
    for disk in root.iter("disk"):
        if disk.get("type") != "file":
            continue
        source = disk.find("source")
        if source is None:
            continue
        if path := source.get("file"):
            return Path(path)
    return None


def _disk_chain(xml: str) -> list[Path]:
    """File backed storage of a domain, backing stores included."""
    root = ET.fromstring(xml)
    paths: list[Path] = []
    for disk in root.iter("disk"):
        if disk.get("type") != "file":
            continue
        for source in disk.iter("source"):
            if path := source.get("file"):
                paths.append(Path(path))
    return paths


def _snapshot_xml(name: str, backing: Path) -> str:
    """Description of a snapshot, telling where its storage has to be.

    libvirt records the storage of an external snapshot in a way that
    depends on its version, so the backing file is kept in the description
    of the snapshot.

    """
    return (
        "<domainsnapshot>"
        f"<name>{name}</name>"
        f"<description>backing={backing}</description>"
        "</domainsnapshot>"
    )


def _snapshot_backing(xml: str) -> Path | None:
    """Backing file of a snapshot, as recorded by :func:`_snapshot_xml`."""
    root = ET.fromstring(xml)
    description = root.findtext("description") or ""
    for token in description.split():
        if token.startswith("backing="):
            return Path(token.removeprefix("backing="))
    return None


def _without_backing_stores(xml: str) -> str:
    """Domain description without the storage chain a snapshot recorded.

    A chain left in the definition keeps qemu from opening the read-only
    base disk of the machine. libvirt rediscovers the chain from the
    storage itself.

    """
    root = ET.fromstring(xml)
    for disk in root.iter("disk"):
        for backing in list(disk.findall("backingStore")):
            disk.remove(backing)
    return ET.tostring(root, encoding="unicode")


def _volume_xml(name: str, backing: Path, size_gib: int) -> str:
    """Storage description, owned as the pool wants it.

    The owner and group are left to the pool: qemu needs to write the
    storage of a running machine.

    """
    return f"""
    <volume type='file'>
      <name>{name}</name>
      <capacity unit='GiB'>{size_gib}</capacity>
      <allocation unit='B'>0</allocation>
      <target>
        <format type='qcow2'/>
        <permissions>
          <mode>0644</mode>
        </permissions>
      </target>
      <backingStore>
        <path>{backing.absolute()}</path>
        <format type='qcow2'/>
      </backingStore>
    </volume>
    """


class LibvirtProxy(HypervisorProxy):
    conn: libvirt.virConnect
    domains: Domains
    imds_host: str
    imds_port: int

    def __init__(self, config: Config):
        self.conn = _initialize_connection()
        self.domains = config.hosts
        self.imds_host = config.imds_host
        self.imds_port = config.imds_port

    @override
    async def close(self):
        self.conn.close()

    @overload
    async def check(self) -> list[Machine]: ...

    @overload
    async def check(self, machine: Machine) -> Machine: ...

    @override
    async def check(self, machine: Machine | None = None) -> list[Machine] | Machine:
        if machine is None:
            machines: list[Machine] = []
            LOGGER.debug("Checking state of machines…")
            tasks: list[Coroutine[Any, Any, Machine]] = []

            for domain_type, names in self.domains.items():
                for name in names:
                    tasks.append(self._check(Machine(domain_type, name)))

            machines = await asyncio.gather(*tasks)
            return machines
        return await self._check(machine)

    async def _check(self, machine: Machine) -> Machine:
        name = machine.name
        try:
            domain = self.conn.lookupByName(name)
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_DOMAIN:
                machine.state = MachineState.ABSENT
            else:
                LOGGER.warning("Lookup failed for domain %s: %s", name, e)
                machine.state = MachineState.UNKNOWN
        else:
            info = domain.info()
            try:
                state = _convert_libvirt_state(int(info[0]))
            except UnsupportedDomainState:
                machine.state = MachineState.UNKNOWN
                LOGGER.warning("Unsupported machine state %s %s", name, info[0])
            else:
                LOGGER.debug("Machine info %s %s", name, info)
                machine.state = state
        return machine

    @override
    async def create(self, machine: Machine) -> bool:
        """Create a libvirt domain for the given machine.

        The created domain has a dedicated storage.

        """
        LOGGER.debug("Defining domain %s", machine.name)
        storage_path: Path | None = None
        try:
            base_disk_path = self._ensure_base_disk()
            storage_path = await self._create_storage(machine, base_disk_path)
            await self._define_domain(machine, storage_path)
        except libvirt.libvirtError as e:
            LOGGER.exception("Failed to define domain %s", machine.name)
            if storage_path is not None:
                self._remove_storage(storage_path)
            return False
        return True

    @override
    async def start(self, machine: Machine) -> bool:
        LOGGER.debug("Creation of domain %s", machine.name)
        try:
            domain = self.conn.lookupByName(machine.name)
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_DOMAIN:
                LOGGER.error("Unknown domain %s", machine.name)
            else:
                LOGGER.exception("Failed to lookup domain %s", machine.name)
            return False
        state, _ = domain.state()
        if state == libvirt.VIR_DOMAIN_RUNNING:
            LOGGER.debug("Domain already running %s", machine.name)
            return True
        domain.create()
        tries = 0
        while not domain.isActive():
            if tries > 60:
                return False
            LOGGER.debug("Waiting for domain %s to start…", machine.name)
            await asyncio.sleep(1)
            tries += 1
        return True

    @override
    async def stop(self, machine: Machine) -> bool:
        LOGGER.debug("Shutdown of domain %s", machine.name)
        try:
            domain = self.conn.lookupByName(machine.name)
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_DOMAIN:
                LOGGER.error("Unknown domain %s", machine.name)
                return True
            else:
                LOGGER.exception("Failed to lookup domain %s", machine.name)
                return False
        state, _ = domain.state()
        if state == libvirt.VIR_DOMAIN_SHUTOFF:
            LOGGER.debug("Domain already shutdown %s", machine.name)
            return True
        elif state != libvirt.VIR_DOMAIN_SHUTDOWN:
            domain.destroy()
        tries = 0
        while domain.isActive():
            if tries > 60:
                return False
            LOGGER.debug("Waiting for domain %s to shutdown…", machine.name)
            await asyncio.sleep(1)
            tries += 1

        return True

    @override
    async def delete(self, machine: Machine) -> bool:
        """Delete domain resources.

        The deletion includes snapshots and storage.

        """
        name = machine.name
        LOGGER.debug("Deleting resources of domain %s", name)
        try:
            domain = self.conn.lookupByName(name)
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_DOMAIN:
                LOGGER.error("Unknown domain %s", name)
                return True
            else:
                LOGGER.exception("Failed to lookup domain %s", name)
                return False
        state, _ = domain.state()
        if state != libvirt.VIR_DOMAIN_SHUTOFF:
            domain.shutdown()
        tries = 0
        while domain.isActive():
            if tries > 60:
                domain.destroy()
                # leaves the domain shutdoff due to the on_poweroff
                # element of XML definition
                break
            LOGGER.debug("Waiting for domain %s to shutdown…", name)
            await asyncio.sleep(1)
            tries += 1

        xml_desc = domain.XMLDesc()
        flags = (
            libvirt.VIR_DOMAIN_UNDEFINE_NVRAM
            | libvirt.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE
            | libvirt.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA
        )
        # The backing stores of the snapshots have to be read before the
        # metadata is dropped, a restored domain no longer records them.
        paths = [*_disk_chain(xml_desc), *self._snapshot_storages(domain)]
        domain.undefineFlags(flags)
        # The base disk is shared with the other machines and left alone.
        paths = [p for p in paths if p.name != BASE_DISK_FILENAME]
        if len(paths) == 0:
            LOGGER.warning("No file backed storage to remove for domain %s", name)
        self._remove_storage(paths)
        return True

    @override
    async def snapshot(self, machine: Machine, name: str) -> bool:
        """Create a disk only snapshot of the machine.

        First stop the machine (to avoid a snapshot in the middle of a
        package installation).

        libvirt then creates an overlay in the storage pool, rewrites the
        domain to use it and keeps its previous storage as a backing store.
        That previous storage, left untouched, is the state to restore.

        """
        domain = self._lookup(machine)
        if domain is None:
            return False
        if name in domain.snapshotListNames():
            LOGGER.error("Snapshot %s already exists for domain %s", name, machine.name)
            return False

        backing = _disk_source(domain.XMLDesc())
        if backing is None:
            LOGGER.error("No file backed storage to snapshot for %s", machine.name)
            return False

        was_active = domain.isActive()
        if was_active and not await self._shutdown(domain):
            return False

        flags = libvirt.VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY
        if domain.isActive():
            flags |= libvirt.VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC
        try:
            domain.snapshotCreateXML(_snapshot_xml(name, backing), flags)
        except libvirt.libvirtError:
            LOGGER.exception("Failed to snapshot domain %s", machine.name)
            return False

        if not was_active:
            return True
        return self._redefine(domain) and await self.start(machine)

    @override
    async def restore(self, machine: Machine, name: str) -> bool:
        """Revert the machine to the given snapshot.

        The overlay written since the snapshot is dropped and replaced by
        an empty one over the same backing store.

        """
        domain = self._lookup(machine)
        if domain is None:
            return False
        try:
            snapshot = domain.snapshotLookupByName(name)
        except libvirt.libvirtError:
            LOGGER.exception("No snapshot %s for domain %s", name, machine.name)
            return False

        backing = _snapshot_backing(snapshot.getXMLDesc())
        overlay = _disk_source(domain.XMLDesc())
        if backing is None or overlay is None:
            LOGGER.error("Failed to read the storage of %s", machine.name)
            return False
        if overlay == backing:
            LOGGER.debug("Machine %s already uses its snapshot storage", machine.name)
        else:
            await self.stop(machine)
            if not self._reset_overlay(overlay, backing):
                return False

        return self._redefine(domain) and await self.start(machine)

    def _lookup(self, machine: Machine) -> libvirt.virDomain | None:
        try:
            return self.conn.lookupByName(machine.name)
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_DOMAIN:
                LOGGER.error("Unknown domain %s", machine.name)
            else:
                LOGGER.exception("Failed to lookup domain %s", machine.name)
            return None

    def _redefine(self, domain: libvirt.virDomain) -> bool:
        """Redefine a domain without the storage chain a snapshot recorded.

        A chain left in the definition keeps qemu from opening the read-only
        base disk of the machine.

        """
        try:
            self.conn.defineXML(_without_backing_stores(domain.XMLDesc()))
        except libvirt.libvirtError:
            LOGGER.exception("Failed to redefine domain %s", domain.name())
            return False
        return True

    async def _shutdown(self, domain: libvirt.virDomain) -> bool:
        """Ask a domain to stop and wait for it."""
        LOGGER.debug("Shutting down domain %s", domain.name())
        try:
            domain.shutdown()
        except libvirt.libvirtError:
            LOGGER.exception("Failed to shutdown domain %s", domain.name())
            return False
        tries = 0
        while domain.isActive():
            if tries > SHUTDOWN_TRIES:
                LOGGER.error("Domain %s is still running", domain.name())
                return False
            await asyncio.sleep(1)
            tries += 1
        return True

    def _snapshot_storages(self, domain: libvirt.virDomain) -> list[Path]:
        """Storages the snapshots of a domain were taken from."""
        paths: list[Path] = []
        for name in domain.snapshotListNames():
            try:
                backing = _snapshot_backing(
                    domain.snapshotLookupByName(name).getXMLDesc()
                )
            except libvirt.libvirtError:
                LOGGER.warning("Failed to read snapshot %s of %s", name, domain.name())
                continue
            if backing is not None:
                paths.append(backing)
        return paths

    def _reset_overlay(self, overlay: Path, backing: Path) -> bool:
        pool = self._get_storage_pool()
        self._refresh_pool(pool)
        try:
            self.conn.storageVolLookupByPath(str(overlay)).delete()
        except libvirt.libvirtError:
            LOGGER.warning("Failed to remove storage %s", overlay)
        try:
            pool.createXML(_volume_xml(overlay.name, backing, DISK_VIRTUAL_SIZE_GIB), 0)
        except libvirt.libvirtError:
            LOGGER.exception("Failed to create storage %s", overlay)
            return False
        return True

    def _remove_storage(self, paths: Path | Sequence[Path | str | None]):
        self._refresh_pool(self._get_storage_pool())
        paths = [paths] if isinstance(paths, Path) else paths
        for p in paths:
            if p is None:
                continue
            try:
                vol = self.conn.storageVolLookupByPath(str(p))
                vol.delete()
            except libvirt.libvirtError:
                LOGGER.warning("Failed to remove storage %s", p)

    def _refresh_pool(self, pool: libvirt.virStoragePool):
        """Make storages created outside of the pool, eg. snapshots, known."""
        try:
            pool.refresh(0)
        except libvirt.libvirtError:
            LOGGER.warning("Failed to refresh storage pool %s", pool.name())

    def _get_storage_pool(self) -> libvirt.virStoragePool:
        try:
            pool = self.conn.storagePoolLookupByName("default")
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_STORAGE_POOL:
                raise RuntimeError("Default storage pool not defined") from e
            raise
        return pool

    def _ensure_base_disk(self) -> Path:
        pool = self._get_storage_pool()
        target = Path(STORAGE_POOL_PATH) / BASE_DISK_FILENAME
        if not target.is_file():
            raise RuntimeError(f"Base disk missing at {target}. Provision it as root")
        return target

    async def _create_storage(self, machine: Machine, base_disk: Path) -> Path:
        """Create storage for the given machine.

        The created storage is a ``.qcow2`` file with backing store.
        The backing store refers to the read-only base disk.

        """
        pool = self._get_storage_pool()
        name = f"{machine.name}.qcow2"
        try:
            vol = pool.storageVolLookupByName(name)
            return Path(vol.path())
        except libvirt.libvirtError as e:
            if e.get_error_code() != libvirt.VIR_ERR_NO_STORAGE_VOL:
                raise e
            LOGGER.debug("Will create storage %s", name)

        vol = pool.createXML(_volume_xml(name, base_disk, DISK_VIRTUAL_SIZE_GIB), 0)
        return Path(vol.path())

    async def _define_domain(
        self,
        machine: Machine,
        storage_path: Path,
    ):
        """Define a domain for the given machine."""
        name = machine.name
        try:
            self.conn.lookupByName(name)
            LOGGER.debug("Domain already exists %s", name)
            return
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_DOMAIN:
                LOGGER.debug("Will create domain %s", name)
            else:
                raise e

        imds_url = f"http://{self.imds_host}:{self.imds_port}"
        mac = machine.mac
        xml = f"""
        <domain type='kvm'>
          <name>{name}</name>
          <memory unit='MiB'>1024</memory>
          <vcpu>2</vcpu>
          <os>
            <type arch='x86_64' machine='q35'>hvm</type>
            <smbios mode='sysinfo'/>
            <boot dev='hd'/>
          </os>
          <sysinfo type='smbios'>
            <system>
              <entry name='serial'>ds=nocloud-net;s={imds_url}/{name}/</entry>
            </system>
          </sysinfo>
          <features>
            <acpi/>
            <apic/>
          </features>
          <cpu mode='host-passthrough'/>
          <clock offset='utc'/>
          <on_poweroff>destroy</on_poweroff>
          <on_reboot>restart</on_reboot>
          <on_crash>destroy</on_crash>
          <devices>
            <emulator>/usr/bin/qemu-system-x86_64</emulator>
            <disk type='file' device='disk'>
              <driver name='qemu' type='qcow2'/>
              <source file='{storage_path}'/>
              <target dev='vda' bus='virtio'/>
            </disk>
            <interface type='network'>
              <source network='default'/>
              <mac address='{mac}'/>
            </interface>
            <console type='pty'>
              <target type='serial' port='0'/>
            </console>
            <channel type='unix'>
              <target type='virtio' name='org.qemu.guest_agent.0'/>
            </channel>
            <graphics type='spice' autoport='yes'/>
            <video>
              <model type='virtio'/>
            </video>
          </devices>
        </domain>
        """
        self.conn.defineXML(xml)
