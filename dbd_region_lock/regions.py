"""AWS regions Dead by Daylight matchmakes into, and their ping beacon hosts.

DBD picks a region by pinging Amazon GameLift beacons in every region and
taking the lowest latency. If the beacons of every region except one are
unreachable, the game can only measure (and therefore match into) that one.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Region:
    code: str
    name: str

    @property
    def beacon_hosts(self) -> tuple[str, ...]:
        """Hostnames the game pings to measure latency to this region."""
        return (
            f"gamelift.{self.code}.amazonaws.com",
            f"gamelift-ping.{self.code}.api.aws",
        )


REGIONS: tuple[Region, ...] = (
    Region("us-east-1", "US East (N. Virginia)"),
    Region("us-east-2", "US East (Ohio)"),
    Region("us-west-1", "US West (N. California)"),
    Region("us-west-2", "US West (Oregon)"),
    Region("ca-central-1", "Canada (Central)"),
    Region("sa-east-1", "South America (Sao Paulo)"),
    Region("eu-west-1", "Europe (Ireland)"),
    Region("eu-west-2", "Europe (London)"),
    Region("eu-central-1", "Europe (Frankfurt)"),
    Region("ap-south-1", "Asia Pacific (Mumbai)"),
    Region("ap-east-1", "Asia Pacific (Hong Kong)"),
    Region("ap-northeast-1", "Asia Pacific (Tokyo)"),
    Region("ap-northeast-2", "Asia Pacific (Seoul)"),
    Region("ap-southeast-1", "Asia Pacific (Singapore)"),
    Region("ap-southeast-2", "Asia Pacific (Sydney)"),
)

BY_CODE: dict[str, Region] = {r.code: r for r in REGIONS}


def get(code: str) -> Region:
    try:
        return BY_CODE[code]
    except KeyError:
        valid = ", ".join(BY_CODE)
        raise ValueError(f"Unknown region {code!r}. Valid regions: {valid}") from None


def others(keep: str) -> list[Region]:
    """Every region except the one to keep."""
    get(keep)
    return [r for r in REGIONS if r.code != keep]
