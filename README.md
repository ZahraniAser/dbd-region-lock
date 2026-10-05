# DBD Region Lock

Small desktop app that locks Dead by Daylight to the AWS region you pick. It
firewall-blocks the ping beacons of every other region, scoped to the DBD
executable, so the game can only measure and match into the one you chose.
Windows and Linux (Proton works).

## How it works

DBD chooses a matchmaking region by pinging Amazon GameLift beacons
(`gamelift.<region>.amazonaws.com`, `gamelift-ping.<region>.api.aws`) in every
region and picking the lowest latency. This app resolves the beacons of every
region **except** the one you choose and adds firewall rules that block them:

| Platform | Mechanism | Scope |
| --- | --- | --- |
| Windows | Windows Defender Firewall outbound rules, one per blocked region, named `DBD Region Lock - <region>` | Only the DBD executable (`program=`). Rules persist across reboots. |
| Linux / Proton | An nftables table `inet dbd_region_lock` | System-wide, but only for GameLift beacon IPs, which serve nothing else. Cleared on reboot. |

The app never touches the game process, its memory or its files. It only adds
firewall rules, which is the same thing as a user editing their own firewall.

## Windows: run it right away

**Option A: download the .exe (no install).** Open the repository's
**Releases** page, download `DBDRegionLock.exe` from the `latest` release and
double-click it. Accept the admin prompt (firewall rules need admin rights).
Windows SmartScreen may warn because the file is not code-signed: click
**More info → Run anyway**.

**Option B: run from source.** Install Python 3.10+ from python.org (tick
"Add python.exe to PATH"), then double-click `Start DBD Region Lock.bat`.

**Build the .exe yourself:** double-click `build_windows.bat`; the file
appears in `dist\DBDRegionLock.exe`. GitHub Actions also builds it on every
push (see `.github/workflows/build.yml`).

![DBD Region Lock](assets/screenshot.png)

### Using it

1. The **GAME** bar shows the detected executable (Steam, Epic, Microsoft
   Store / Game Pass). If it says *Not found*, click **Change…** and pick
   `DeadByDaylight-*-Shipping.exe` in `...\DeadByDaylight\Binaries\Win64`
   (or `WinGDK` for the Microsoft Store version).
2. Click a region card. Pings are colour-coded (green < 80 ms, yellow < 150 ms,
   red above). **Pick best ping** selects the fastest one for you.
3. Press **LOCK TO …**. The badge top-right turns red and the card shows
   **● LOCKED**. Restart the game if it was running; the app tells you.
4. **Unlock all** removes every rule the app created.

The ping on the cards is measured by this app, not the game, so it still shows
real latency to blocked regions.

## Linux (Steam Proton)

```sh
sudo python3 -m dbd_region_lock               # GUI (needs python3-tk)
sudo python3 -m dbd_region_lock lock eu-west-1
sudo python3 -m dbd_region_lock unlock
```

Without root it runs `nft` through `pkexec` or `sudo`. Requires nftables.

## Command line (both platforms)

```
python -m dbd_region_lock regions              # list regions and latency
python -m dbd_region_lock lock <region> [--exe PATH]
python -m dbd_region_lock unlock
python -m dbd_region_lock status
```

## Notes and limitations

- **Anti-cheat:** Easy Anti-Cheat protects the game process. This app never
  interacts with that process; it only changes OS firewall rules, and region
  selectors that work this way are widely used. That said, no third-party
  tool can guarantee how Behaviour Interactive treats it, so use at your own
  discretion.
- Beacon DNS answers can change over time. If a blocked region starts
  appearing again, click **Lock** again to refresh the IPs.
- Locking to a far-away region means high ping in matches, and queues can be
  longer in small regions.
- Locking does not change the region of a lobby you are already in; restart
  the game after locking or unlocking.

## Customizing

- **Regions:** `dbd_region_lock/regions.py` is one list; add, remove or rename
  entries there and the app and CLI pick them up.
- **Look:** the colours, ping thresholds and number of card columns are
  constants at the top of `dbd_region_lock/gui.py`.
- **Firewall logic:** `dbd_region_lock/firewall/windows.py` (netsh) and
  `firewall/linux.py` (nftables).

## Tests

```sh
pip install pytest
python -m pytest
```
