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

## Windows

### Run from source

1. Install Python 3.10+ from python.org (tkinter is included).
2. From this folder: `python -m dbd_region_lock`
3. Accept the UAC prompt (firewall rules need administrator rights).

### Build a single .exe

Run `build_windows.bat`. It produces `dist\DBDRegionLock.exe`, which asks for
admin rights when launched.

### Using it

1. The game executable is detected automatically for Steam, Epic and the
   Microsoft Store / Game Pass. If it is not found, click **Browse…** and pick
   `DeadByDaylight-*-Shipping.exe` in `...\DeadByDaylight\Binaries\Win64`
   (or `WinGDK` for the Microsoft Store version).
2. Pick a region and click **Lock to selected region**.
3. Restart the game. You can only queue into that region now.
4. **Unlock (all regions)** removes every rule the app created.

The ping column is measured by this app, not by the game, so it still shows
real latency to blocked regions on Windows.

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

## Tests

```sh
pip install pytest
python -m pytest
```
