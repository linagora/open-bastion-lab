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

type Domains = dict[Role, list[str]]


def _libvirt_error_handler(
    logger: logging.Logger,
    error: list
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
                state = _convert_libvirt_state(info[0])
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
        root = ET.fromstring(xml_desc)
        # The disk type is an attribute of <disk>, the path one of its
        # <source>.
        paths = [
            source.get("file")
            for disk in root.findall("./devices/disk")
            if disk.get("type") == "file"
            and (source := disk.find("source")) is not None
        ]
        if len(paths) == 0:
            LOGGER.warning("No file backed storage to remove for domain %s", name)
        flags = (
            libvirt.VIR_DOMAIN_UNDEFINE_NVRAM
            | libvirt.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE
            | libvirt.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA
        )
        domain.undefineFlags(flags)
        self._remove_storage(paths)
        return True

    def _remove_storage(self, paths: Path | Sequence[Path | str | None]):
        paths = [paths] if isinstance(paths, Path) else paths
        for p in paths:
            if p is None:
                continue
            try:
                vol = self.conn.storageVolLookupByPath(p)
                vol.delete()
            except libvirt.libvirtError:
                LOGGER.warning("Failed to remove storage %s", p)

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
            if e.get_error_code() == libvirt.VIR_ERR_NO_STORAGE_VOL:
                LOGGER.debug("Will create storage %s", name)
            else:
                raise e

        virtual_size_gib = DISK_VIRTUAL_SIZE_GIB
        xml = f"""
        <volume type='file'>
          <name>{name}</name>
          <capacity unit='GiB'>{virtual_size_gib}</capacity>
          <allocation unit='B'>0</allocation>
          <target>
            <format type='qcow2'/>
            <permissions>
              <mode>0644</mode>
              <owner>0</owner>
              <group>0</group>
            </permissions>
          </target>
          <backingStore>
            <path>{base_disk.absolute()}</path>
            <format type='qcow2'/>
          </backingStore>
        </volume>
        """
        vol = pool.createXML(xml, 0)
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
            <graphics type='spice' autoport='yes'/>
            <video>
              <model type='virtio'/>
            </video>
          </devices>
        </domain>
        """
        self.conn.defineXML(xml)
