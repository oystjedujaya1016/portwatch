# portwatch

Lightweight CLI daemon that monitors open ports and alerts on unexpected changes.

## Installation

```bash
go install github.com/yourname/portwatch@latest
```

Or build from source:

```bash
git clone https://github.com/yourname/portwatch.git && cd portwatch && go build -o portwatch .
```

## Usage

Start the daemon with a baseline scan of your current open ports:

```bash
portwatch start
```

Watch a specific interface and get alerted when new ports open or existing ones close:

```bash
portwatch start --interval 30s --alert email --config config.yaml
```

Example alert output:

```
[ALERT] 2024-01-15 10:42:03 - New port detected: TCP 0.0.0.0:8080
[ALERT] 2024-01-15 10:43:17 - Port closed: TCP 0.0.0.0:3000
```

Snapshot current open ports to use as a trusted baseline:

```bash
portwatch snapshot --output baseline.json
```

### Common Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--interval` | `60s` | How often to scan for port changes |
| `--config` | `~/.portwatch.yaml` | Path to config file |
| `--quiet` | `false` | Suppress output, only log alerts |

## License

MIT © [yourname](https://github.com/yourname)