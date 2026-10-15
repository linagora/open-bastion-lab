"""Instance metadata service (IMDS).

Or 90% of an IMDS since it don't listen on 169.254.169.254.

"""

from collections import defaultdict
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
import logging

from aiohttp import web
import yaml

from open_bastion_lab.config import Config
from open_bastion_lab.machine import ip_by_name, mac_by_name

LOGGER = logging.getLogger(__name__)

CLOUD_CONFIG_HEADER = "#cloud-config"


def _is_cloud_config(content: str) -> bool:
    """Tells whether the given user-data is a cloud-config payload."""
    return content.lstrip().startswith(CLOUD_CONFIG_HEADER)


@dataclass
class SeedCollect:
    network_config: bool = False
    meta_data: bool = False
    user_data: bool = False
    vendor_data: bool = False

    def collect(self, name: str):
        if name == "network-config":
            self.network_config = True
        elif name == "meta-data":
            self.meta_data = True
        elif name == "user-data":
            self.user_data = True
        elif name == "vendor-data":
            self.vendor_data = True

    def seeded(self) -> bool:
        return all([
            self.network_config, self.meta_data, self.user_data, self.vendor_data])


class InstanceMetadataServer:
    fleet: str
    authorized_keys: list[str]
    host: str
    port: int
    app: web.Application
    _runner: web.AppRunner | None
    _seeded: defaultdict[str, SeedCollect]

    def __init__(self, config: Config):
        self.fleet = config.fleet
        self.authorized_keys = config.authorized_keys
        self.host = "0.0.0.0"
        # listen on all interfaces, don't use config.imds_host
        self.port = config.imds_port
        self.app = web.Application()
        self.app.router.add_get("/{name}/{kind}", self.handle_seed)
        self._runner = None
        self._seeded = defaultdict(SeedCollect)

    async def handle_seed(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        kind = request.match_info["kind"]
        if kind not in ("user-data", "meta-data", "vendor-data", "network-config"):
            raise web.HTTPNotFound()

        resource = (
            files("open_bastion_lab") / "data" / "fleet" / self.fleet / name / kind
        )
        if not resource.is_file():
            raise web.HTTPNotFound()

        body = await self.render_seed(resource, kind, name)
        if body is None:
            raise web.HTTPNotFound()

        self._seeded[name].collect(kind)
        return web.Response(
            text=body,
            content_type="text/cloud-config" if kind == "user-data" else "text/yaml",
        )

    def seeded(self, name: str) -> bool:
        return self._seeded[name].seeded()

    async def render_seed(self, resource: Traversable, kind: str, name: str) -> str:
        """Specialize the content of user-data, network-config, etc. files."""
        content = resource.read_text()
        if kind != "user-data" and kind != "network-config":
            assert(not _is_cloud_config(content))
            return content

        parsed = yaml.safe_load(content) or {}
        if kind == "network-config":
            config = parsed.get("config", [])
            if len(config) == 0:
                return content

            config[0]["mac_address"] = mac_by_name(name)
            config[0]["subnets"][0]["address"] = ip_by_name(name)

        elif kind == "user-data":
            users = parsed.get("users", [])
            if len(users) == 0:
                return content

            users[0]["ssh_authorized_keys"] = self.authorized_keys

        body = yaml.safe_dump(parsed, sort_keys=False, width=4096)
        if _is_cloud_config(content):
            # Dumping the parsed document loses the leading comment but
            # cloud-init selects the user-data handler from the payload
            # itself!
            return f"{CLOUD_CONFIG_HEADER}\n{body}"
        else:
            return body

    async def start(self) -> None:
        if self._runner is None:
            LOGGER.debug("Starting instance metadata service…")
            self._runner = web.AppRunner(self.app, access_log=LOGGER)
            await self._runner.setup()
            await web.TCPSite(self._runner, self.host, self.port).start()

    async def stop(self) -> None:
        if self._runner is not None:
            LOGGER.debug("Stopping instance metadata service…")
            await self._runner.cleanup()
            self._runner = None
