"""Port forwarding through the bastion: what it reaches, and what it leaves."""

from pytest_bdd import scenario

FEATURE = "port_forwarding.feature"


@scenario(
    FEATURE, "An SSO user reaches a port of a backend through a forwarded channel"
)
def test_forwarded_channel() -> None:
    pass


@scenario(
    FEATURE, "An SSO user cannot reach a backend through the bastion with ProxyJump"
)
def test_proxy_jump_to_a_backend() -> None:
    pass


@scenario(FEATURE, "A bastion that refuses TCP forwarding refuses the channel")
def test_forwarding_closed() -> None:
    pass
