import socket
import threading
from pathlib import Path

import pytest

from dbd_region_lock import core, detect, hostsfile, regions, resolver, state
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


class FakeFirewall:
    def __init__(self):
        self.applied, self.added, self.removed = {}, [], False

    def apply(self, exe, blocked):
        self.applied = dict(blocked)
        return []

    def add(self, exe, blocked):
        self.added.append(blocked)

    def remove(self):
        self.removed = True

    def can_refresh(self):
        return True


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Isolate core from the real firewall, hosts file, state file and process list."""
    fw = FakeFirewall()
    monkeypatch.setattr(core, "get_firewall", lambda: fw)
    monkeypatch.setattr(core.detect, "game_running", lambda: False)
    monkeypatch.setattr(core.hostsfile, "clean", lambda: 0)
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(state, "state_path", lambda: state_file)
    return fw


def test_lock_never_blocks_kept_region_ips(monkeypatch, env):
    def fake_resolve(rs):
        return {r.code: {"9.9.9.9", f"10.0.0.{i}"} for i, r in enumerate(rs)}

    monkeypatch.setattr(core.resolver, "resolve_regions", fake_resolve)
    core.lock("eu-central-1", "dbd.exe")
    assert "eu-central-1" not in env.applied
    assert all("9.9.9.9" not in ips for ips in env.applied.values())
    assert state.load().region == "eu-central-1"


def test_lock_and_unlock_refused_while_game_runs(monkeypatch, env):
    monkeypatch.setattr(core.detect, "game_running", lambda: True)
    with pytest.raises(core.GameRunningError):
        core.lock("eu-central-1", "dbd.exe")
    with pytest.raises(core.GameRunningError):
        core.unlock()
    assert env.applied == {} and not env.removed


def test_refresh_adds_only_new_ips(monkeypatch, env):
    rounds = iter([{"1.1.1.1"}, {"1.1.1.1", "2.2.2.2"}])
    current = {}

    def fake_resolve(rs):
        return {r.code: set() if r.code == "eu-central-1" else set(current["ips"]) for r in rs}

    monkeypatch.setattr(core.resolver, "resolve_regions", fake_resolve)
    current["ips"] = next(rounds)
    core.lock("eu-central-1", "dbd.exe")
    assert core.refresh() == 0
    current["ips"] = next(rounds)
    assert core.refresh() == len(regions.REGIONS) - 1  # 2.2.2.2 for each blocked region
    assert all(ips == {"2.2.2.2"} for ips in env.added[0].values())
    assert core.refresh() == 0


def test_refresh_skipped_while_game_runs(monkeypatch, env):
    state.save(state.LockState("eu-central-1", "dbd.exe", set()))
    monkeypatch.setattr(core.detect, "game_running", lambda: True)
    monkeypatch.setattr(core.resolver, "resolve_regions", lambda rs: pytest.fail("should not resolve"))
    assert core.refresh() == 0


def test_unlock_clears_state(env):
    state.save(state.LockState("eu-central-1"))
    core.unlock()
    assert env.removed and state.load() is None


def test_strip_gamelift_hosts_entries():
    text = (
        "# comment gamelift.us-east-1.amazonaws.com\n"
        "127.0.0.1 localhost\n"
        "3.1.2.3 gamelift.us-east-1.amazonaws.com\n"
        "3.1.2.3 gamelift-ping.eu-west-1.api.aws keep.example # note\n"
    )
    cleaned, removed = hostsfile.strip_gamelift(text)
    assert removed == 2
    assert cleaned == (
        "# comment gamelift.us-east-1.amazonaws.com\n"
        "127.0.0.1 localhost\n"
        "3.1.2.3 keep.example # note\n"
    )


def test_clean_hosts_writes_backup(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n1.2.3.4 gamelift-ping.ap-east-1.api.aws\n")
    assert hostsfile.clean(hosts) == 1
    assert hosts.read_text() == "127.0.0.1 localhost\n"
    assert "gamelift" in (tmp_path / ("hosts" + hostsfile.BACKUP_SUFFIX)).read_text()
    assert hostsfile.clean(hosts) == 0


def test_state_round_trip(tmp_path):
    path = tmp_path / "s.json"
    state.save(state.LockState("us-west-2", "x.exe", {"1.2.3.4"}), path)
    assert state.load(path) == state.LockState("us-west-2", "x.exe", {"1.2.3.4"})
    state.clear(path)
    assert state.load(path) is None


def test_udp_ping_measures_echo():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]

    def echo():
        data, addr = server.recvfrom(512)
        server.sendto(data, addr)

    threading.Thread(target=echo, daemon=True).start()
    assert resolver.udp_ping("127.0.0.1", port, timeout=2) is not None
    server.close()


def test_udp_ping_times_out_without_answer():
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))
    assert resolver.udp_ping("127.0.0.1", silent.getsockname()[1], timeout=0.2) is None
    silent.close()


def test_nft_add_elements():
    script = linux.add_elements({"a": {"1.2.3.4"}, "b": {"2600::1"}})
    assert "add element inet dbd_region_lock blocked4 { 1.2.3.4 }" in script
    assert "add element inet dbd_region_lock blocked6 { 2600::1 }" in script
    assert linux.add_elements({"a": set()}) == ""


def test_game_running_detects_proton(monkeypatch):
    monkeypatch.setattr(detect.sys, "platform", "linux")
    monkeypatch.setattr(detect, "_linux_cmdlines", lambda: [
        "steam", "Z:\\steamapps\\common\\Dead by Daylight\\DeadByDaylight-Win64-Shipping.exe -foo",
    ])
    assert detect.game_running()
    monkeypatch.setattr(detect, "_linux_cmdlines", lambda: ["steam", "bash"])
    assert not detect.game_running()


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


def test_locked_region_is_the_one_left_open():
    blocked = [r.code for r in regions.others("ap-southeast-2")]
    assert core.locked_region(blocked) == "ap-southeast-2"
    assert core.locked_region([]) is None
    assert core.locked_region(blocked[:3]) is None


def test_every_region_has_an_area():
    assert set(regions.AREAS) == {"Americas", "Europe", "Asia Pacific"}
    assert all(r.city for r in regions.REGIONS)
