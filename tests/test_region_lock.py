from pathlib import Path

import pytest

from dbd_region_lock import core, detect, regions
from dbd_region_lock.firewall import linux, windows


def test_others_excludes_kept_region():
    others = regions.others("eu-central-1")
    assert len(others) == len(regions.REGIONS) - 1
    assert "eu-central-1" not in {r.code for r in others}


def test_unknown_region_rejected():
    with pytest.raises(ValueError):
        regions.others("mars-1")


def test_beacon_hosts():
    assert regions.get("us-east-1").beacon_hosts == (
        "gamelift.us-east-1.amazonaws.com",
        "gamelift-ping.us-east-1.api.aws",
    )


def test_netsh_rule_is_scoped_to_exe():
    exe = r"C:\Games\Dead by Daylight\DeadByDaylight\Binaries\Win64\DeadByDaylight-Win64-Shipping.exe"
    args = windows.add_rule_args("eu-west-1", exe, {"5.6.7.8", "1.2.3.4"})
    assert "name=DBD Region Lock - eu-west-1" in args
    assert "dir=out" in args and "action=block" in args
    assert f"program={exe}" in args
    assert "remoteip=1.2.3.4,5.6.7.8" in args


def test_nft_ruleset_splits_families():
    text = linux.ruleset({"us-east-1": {"1.2.3.4", "2600::1"}, "eu-west-1": {"5.6.7.8"}})
    assert "table inet dbd_region_lock" in text
    assert "elements = { 1.2.3.4, 5.6.7.8 }" in text
    assert "elements = { 2600::1 }" in text
    assert "ip daddr @blocked4 drop" in text


def test_nft_ruleset_empty_sets_are_valid():
    text = linux.ruleset({"us-east-1": set()})
    assert "elements" not in text


def test_lock_never_blocks_kept_region_ips(monkeypatch):
    def fake_resolve(rs):
        return {r.code: {"9.9.9.9", f"10.0.0.{i}"} for i, r in enumerate(rs)}

    applied = {}

    class FakeFirewall:
        def apply(self, exe, blocked):
            applied.update(blocked)
            return []

    monkeypatch.setattr(core.resolver, "resolve_regions", fake_resolve)
    monkeypatch.setattr(core, "get_firewall", lambda: FakeFirewall())
    core.lock("eu-central-1", "dbd.exe")
    assert "eu-central-1" not in applied
    assert all("9.9.9.9" not in ips for ips in applied.values())


def test_steam_library_parsing(tmp_path: Path):
    steamapps = tmp_path / "steamapps"
    steamapps.mkdir()
    (steamapps / "libraryfolders.vdf").write_text(
        '"libraryfolders"\n{\n "0"\n {\n  "path"\t\t"C:\\\\Program Files (x86)\\\\Steam"\n }\n'
        ' "1"\n {\n  "path"\t\t"D:\\\\SteamLibrary"\n }\n}\n'
    )
    libs = detect.steam_library_dirs(tmp_path)
    assert Path("D:\\SteamLibrary") in libs


def test_find_shipping_exe(tmp_path: Path):
    exe = tmp_path / "DeadByDaylight" / "Binaries" / "Win64" / "DeadByDaylight-EGS-Shipping.exe"
    exe.parent.mkdir(parents=True)
    exe.touch()
    assert detect.find_shipping_exe(tmp_path) == exe
