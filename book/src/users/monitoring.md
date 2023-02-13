# Monitoring

Once Trin is running, the following may be useful

## Logs

If errors are encountered, they will be logged to the console in which
Trin was started.

Be aware that The `RUST_LOG` variable allows for control of what logs are visible.

- `RUST_LOG=info cargo run -p trin`
- `RUST_LOG=debug cargo run -p trin`

If started as a systemd service logs will be visible with:
```sh
journalctl -fu <trin-service-name>.service
```

## Disk use

The following locations are where trin stores data by default:
- Mac Os: `~/Library/Application Support/trin`
- Unix-like: `$HOME/.local/share/trin`
```sh
cd /path/to/data
du -sh
```

## CPU and memory use

`htop` can be used to see the CPU and memory used by trin

- Ubuntu: `sudo apt install htop`
- Mac Os: `brew install htop`

```sh
htop
```
