import socket
import struct
import threading
import types
from pathlib import Path

import pytest

from dbd_region_lock import awsranges, core, detect, diagnose, hostsfile, regions, resolver, state, steer
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
    monkeypatch.setattr(core.hostsfile, "has_managed", lambda: False)
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


def _dns_response(query: bytes, records: list[tuple[int, bytes]], rcode: int = 0) -> bytes:
    """A minimal DNS response to `query` carrying (type, rdata) answers, names compressed."""
    header = query[:2] + struct.pack(">HHHHH", 0x8180 | rcode, 1, len(records), 0, 0)
    body = query[12:]
    for rtype, rdata in records:
        body += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata
    return header + body


def test_dns_query_and_parse_round_trip():
    query = resolver.build_query("gamelift-ping.eu-central-1.api.aws", 1)
    assert b"\x0dgamelift-ping\x0ceu-central-1\x03api\x03aws\x00" in query
    cname = (5, b"\x03foo\x00")
    a = (1, socket.inet_pton(socket.AF_INET, "3.122.192.230"))
    aaaa = (28, socket.inet_pton(socket.AF_INET6, "2a05:d014::1"))
    assert resolver.parse_response(_dns_response(query, [cname, a, aaaa])) == {"3.122.192.230", "2a05:d014::1"}
    assert resolver.parse_response(_dns_response(query, [a], rcode=3)) == set()


def test_resolve_hosts_unions_partial_answers_and_drops_dead_resolvers(monkeypatch):
    # Each answer carries one address of a 2-address pool, like the real beacons.
    pool = ["3.0.0.1", "3.0.0.2"]
    calls = {"dead": 0}

    def direct(host, server, qtype):
        if server == resolver.PUBLIC_RESOLVERS[-1]:
            calls["dead"] += 1
            return None
        return {pool[resolver.PUBLIC_RESOLVERS.index(server) % 2]} if qtype == 1 else set()

    monkeypatch.setattr(resolver, "direct_lookup", direct)
    monkeypatch.setattr(resolver, "system_lookup", lambda h: {"0.0.0.0"})  # DNS-blocker answer, ignored
    monkeypatch.setattr(resolver, "doh_lookup", lambda h: {pool[1]})
    monkeypatch.setattr(resolver, "ROUND_DELAY", 0)
    assert resolver.resolve_hosts(["h"]) == {"h": set(pool)}
    assert calls["dead"] == 2  # asked in round one only (A + AAAA), then dropped


def test_usable_filters_dns_blocker_answers():
    assert resolver.usable("3.122.192.230") and resolver.usable("2a05:d014::1")
    assert not any(map(resolver.usable, ["0.0.0.0", "127.0.0.1", "192.168.1.5", "::1", "nonsense"]))


def test_all_apps_rule_has_no_program_filter():
    args = windows.add_rule_args("eu-west-1", "", {"1.2.3.4"})
    assert not any(a.startswith("program=") for a in args)
    assert args[-1] == "remoteip=1.2.3.4"


def test_dns_check_flags_blocked_and_redirected_regions(monkeypatch):
    def lookup(host):
        if "eu-central-1" in host:
            return {"127.0.0.1"}
        if "us-east-1" in host:
            return set()
        return {"3.3.3.3"}

    monkeypatch.setattr(diagnose.resolver, "system_lookup", lookup)
    monkeypatch.setattr(diagnose.hostsfile, "hosts_path", lambda: Path("/nonexistent/hosts"))
    checks = diagnose.dns_checks(kept="us-east-1")
    text = diagnose.report(checks)
    assert "Frankfurt" in text and "N. Virginia" in text
    assert [c.level for c in checks] == [diagnose.FAIL, diagnose.FAIL]


def test_live_check_reports_leaking_region(monkeypatch):
    ips = {r.code: {f"3.0.0.{i}"} for i, r in enumerate(regions.REGIONS)}
    monkeypatch.setattr(diagnose.resolver, "resolve_regions", lambda rs: ips)
    leaking = ips["eu-central-1"] | ips["us-east-1"]  # kept region + one leak
    monkeypatch.setattr(diagnose.resolver, "udp_ping", lambda ip, timeout=0: 20.0 if ip in leaking else None)
    monkeypatch.setattr(diagnose.resolver, "measure_latency", lambda r: 20.0)
    saved = state.LockState("us-east-1", "", set().union(*ips.values()))
    text = diagnose.report(diagnose.lock_checks("us-east-1", saved))
    assert "Still reachable despite the block: Frankfurt" in text
    assert "N. Virginia answers (20 ms)" in text


def test_udp_ping_survives_missing_ip_family(monkeypatch):
    def no_socket(*args, **kwargs):
        raise OSError(97, "Address family not supported by protocol")

    monkeypatch.setattr(resolver.socket, "socket", no_socket)
    assert resolver.udp_ping("2a05:d014::1") is None


def test_third_party_firewall_state_decoding():
    # Norton with firewall on (0x061100) and another product with it off (0x060100).
    on, off = diagnose.third_party_firewalls("397568|Norton 360 for Gamers\n393472|Other FW\ngarbage\n")
    assert on == ["Norton 360 for Gamers"] and off == ["Other FW"]


def test_ranges_by_region_collapses_and_keeps_families():
    data = {
        "prefixes": [
            {"ip_prefix": "3.0.0.0/25", "region": "eu-central-1", "service": "AMAZON"},
            {"ip_prefix": "3.0.0.128/25", "region": "eu-central-1", "service": "EC2"},
            {"ip_prefix": "3.0.0.0/24", "region": "eu-central-1", "service": "EC2"},
        ],
        "ipv6_prefixes": [{"ipv6_prefix": "2a05:d014::/35", "region": "eu-central-1", "service": "EC2"}],
    }
    assert awsranges.ranges_by_region(data) == {"eu-central-1": ["3.0.0.0/24", "2a05:d014::/35"]}


def test_strict_never_blocks_kept_or_backend_region():
    all_ranges = {code: [f"{code}-range"] for code in ("us-east-1", "eu-central-1", "ap-south-1")}
    keep_frankfurt = awsranges.strict_block_list("eu-central-1", list(all_ranges), all_ranges)
    assert keep_frankfurt == {"ap-south-1": ["ap-south-1-range"]}  # us-east-1 hosts the game's backend
    keep_virginia = awsranges.strict_block_list("us-east-1", list(all_ranges), all_ranges)
    assert set(keep_virginia) == {"eu-central-1", "ap-south-1"}


def test_strict_lock_adds_ranges_for_game_only(monkeypatch, env):
    added = {}
    env.add_ranges = lambda exe, ranges: added.update(exe=exe, ranges=ranges)
    monkeypatch.setattr(core.resolver, "resolve_regions", lambda rs: {r.code: {"9.9.9.9"} for r in rs})
    monkeypatch.setattr(core.awsranges, "load", lambda: {r.code: [f"{r.code}/r"] for r in regions.REGIONS})
    notes = core.lock("us-east-1", "", strict_exe="C:\\\\dbd.exe")
    assert added["exe"] == "C:\\\\dbd.exe" and "us-east-1" not in added["ranges"]
    assert len(added["ranges"]) == len(regions.REGIONS) - 1
    assert state.load().strict_exe == "C:\\\\dbd.exe"
    assert any("Strict" in n for n in notes)


def test_strict_download_failure_leaves_firewall_untouched(monkeypatch, env):
    def fail():
        raise RuntimeError("offline")

    monkeypatch.setattr(core.awsranges, "load", fail)
    with pytest.raises(RuntimeError):
        core.lock("us-east-1", "", strict_exe="C:\\\\dbd.exe")
    assert env.applied == {}


def test_windows_rules_split_large_range_lists(monkeypatch):
    calls = []
    monkeypatch.setattr(windows, "_run", lambda args: calls.append(args) or types.SimpleNamespace(returncode=0))
    windows.WindowsFirewall().add_ranges("C:\\\\dbd.exe", {"eu-central-1": [f"3.{i // 256}.{i % 256}.0/24" for i in range(450)]})
    assert len(calls) == 3  # 200 + 200 + 50
    assert all("program=C:\\\\dbd.exe" in c for c in calls)


def test_steer_entries_skip_kept_and_decoy():
    entries = steer.entries_for("eu-west-1", "ap-southeast-2", ["3.3.3.3"], ["4.4.4.4"])
    hosts = {h for _, h in entries}
    assert "gamelift-ping.eu-west-1.api.aws" not in hosts and "gamelift-ping.ap-southeast-2.api.aws" not in hosts
    assert ("3.3.3.3", "gamelift-ping.eu-central-1.api.aws") in entries
    assert ("4.4.4.4", "gamelift.eu-central-1.amazonaws.com") in entries
    assert len(entries) == 2 * (len(regions.REGIONS) - 2)


def _fake_network(monkeypatch, latency):
    """Each region's beacon at 10.0.<i>.1 (+ endpoint 10.1.<i>.1) answering with `latency[code]` ms."""
    index = {r.code: i for i, r in enumerate(regions.REGIONS)}

    def resolve(hosts, **_):
        out = {}
        for h in hosts:
            code = h.split(".")[1]
            out[h] = {f"10.0.{index[code]}.1"} if h.startswith("gamelift-ping") else {f"10.1.{index[code]}.1"}
        return out

    by_ip = {f"10.0.{i}.1": latency.get(code) for code, i in index.items()}
    monkeypatch.setattr(steer.resolver, "resolve_hosts", resolve)
    monkeypatch.setattr(steer.resolver, "udp_ping", lambda ip, **_: by_ip.get(ip))


def test_steer_picks_slowest_answering_region(monkeypatch):
    _fake_network(monkeypatch, {"eu-west-1": 91.0, "eu-central-1": 80.0, "sa-east-1": 310.0, "ap-southeast-2": None})
    plan = steer.plan("eu-west-1")
    assert plan.decoy == "sa-east-1"  # Sydney is farther but doesn't answer
    assert plan.ping_ips == [f"10.0.{[r.code for r in regions.REGIONS].index('sa-east-1')}.1"]
    assert not plan.warnings


def test_steer_refuses_when_kept_region_does_not_answer(monkeypatch):
    _fake_network(monkeypatch, {"eu-central-1": 80.0})
    with pytest.raises(RuntimeError, match="does not answer"):
        steer.plan("eu-west-1")


def test_steer_warns_when_no_region_is_much_slower(monkeypatch):
    _fake_network(monkeypatch, {"eu-west-1": 91.0, "eu-central-1": 100.0})
    assert steer.plan("eu-west-1").warnings


def test_managed_hosts_block_round_trip(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n9.9.9.9 gamelift-ping.us-east-1.api.aws\n")
    hostsfile.write_managed([("3.3.3.3", "gamelift-ping.eu-central-1.api.aws")], hosts)
    text = hosts.read_text()
    assert hostsfile.has_managed(hosts)
    assert "9.9.9.9" not in text and "3.3.3.3 gamelift-ping.eu-central-1.api.aws" in text
    assert text.startswith("127.0.0.1 localhost\n")
    assert hostsfile.clean(hosts) == 1
    assert hosts.read_text() == "127.0.0.1 localhost\n" and not hostsfile.has_managed(hosts)


def test_steer_lock_clears_firewall_and_writes_hosts(monkeypatch, env):
    written = {}
    fake_plan = steer.Plan("eu-west-1", "sa-east-1", 91.0, 310.0, ["3.3.3.3"], ["4.4.4.4"],
                           [("3.3.3.3", "gamelift-ping.eu-central-1.api.aws")], [])
    monkeypatch.setattr(core.steer, "plan", lambda kept: fake_plan)
    monkeypatch.setattr(core.hostsfile, "write_managed", lambda entries: written.update(entries=entries))
    notes = core.lock("eu-west-1", "", mode="steer")
    assert env.removed and written["entries"] == fake_plan.entries
    saved = state.load()
    assert (saved.mode, saved.region, saved.decoy) == ("steer", "eu-west-1", "sa-east-1")
    assert "Sao Paulo" in notes[0]
    monkeypatch.setattr(core.hostsfile, "has_managed", lambda: True)
    assert core.status() == (True, "eu-west-1")
    assert core.refresh() == 0  # beacon refresh is for Block mode only
