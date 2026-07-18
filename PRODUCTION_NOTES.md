# MangoPanel Production Notes

## Install

1. Clone the repository onto the server.
2. Run the installer:

```bash
bash scripts/install.sh --full
```

3. Start MangoPanel:

```bash
bash scripts/service mangopanel start
```

The installer now registers a boot-time service:
- Linux: `systemd`
- macOS: `launchd` LaunchAgent

That means MangoPanel is configured to start again after a reboot.

## Start

```bash
bash scripts/service mangopanel start
```

If you prefer to use the service manager directly:
- Linux: `systemctl start mangopanel`
- macOS: `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.servermango.mangopanel.plist`

## Stop

```bash
bash scripts/service mangopanel stop
```

If you prefer to use the service manager directly:
- Linux: `systemctl stop mangopanel`
- macOS: `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.servermango.mangopanel.plist`

## Status

```bash
bash scripts/service mangopanel status
```

## Logs

- Service log: `var/mangopanel.log`
- PID file: `var/mangopanel.pid`

