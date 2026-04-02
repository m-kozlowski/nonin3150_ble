# Streaming Output

## Pipeline

```
device -> parser -> [transform] -> format -> sink
```

Each stage is independent and configurable via CLI flags.

## Formats (`--format` / `-f`)

| Format | Description |
|--------|-------------|
| `kv` | Key=value pairs (default). `ts=... spo2=98 pulse_rate=72` |
| `csv` | CSV with auto-printed header row |
| `airbridge` | 7-byte binary oximetry packet (see below) |
| `'{...}'` | Custom Python format string. Fields: `{ts}`, `{spo2}`, `{pulse_rate}`, etc. |

## Sinks (`-o`)

| Sink | Description |
|------|-------------|
| *(default)* | stdout |
| `path/to/file` | Write to file |
| `udp:host:port` | Send to UDP endpoint. Hostname resolved once at startup. |

Text formats send one line per packet over UDP. Airbridge sends raw binary.

## Transforms (`--transform` / `-t`)

| Transform | Description |
|-----------|-------------|
| `passthrough` | Every packet as-is (default) |
| `collect` | Merge DF2 25-frame cycle into one record (3 Hz) |
| `collect:field1,field2` | Collect specific fields only |
| `throttle:N` | Rate-limit to N Hz |

Chain with `|`: `collect|throttle:3`

### Collect fields

| Field | DF2 frames | Description |
|-------|-----------|-------------|
| `spo2` | 3 | 4-beat SpO2 average |
| `pulse_rate` | 1-2 | 4-beat HR (9-bit, MSB+LSB) |
| `spo2_display` | 9 | SpO2 formatted for display (1.5s update) |
| `spo2_fast` | 10 | Fast-responding SpO2 |
| `spo2_b2b` | 11 | Beat-to-beat SpO2 |
| `e_spo2` | 16 | 8-beat extended SpO2 |
| `pulse_rate_display` | 20-21 | HR formatted for display |
| `pulse_rate_ext` | 14-15 | 8-beat extended HR |
| `low_battery` | 8 | Battery status flag |
| `smartpoint` | 8 | SmartPoint quality flag |

Default: `spo2,pulse_rate`

Non-DF2 streams (oximetry, df8, df13) pass through collect unchanged.

## Airbridge Protocol

7-byte UDP packet for feeding oximetry data to external systems.

```
Offset  Size  Field
0       2     Magic: 0x55 0xAB
2       1     Flags: 0x00
3       2     SpO2 (16-bit little-endian)
5       2     Heart rate (16-bit little-endian)
```

Invalid/missing readings: `0xFF 0x07` for both fields.

## Examples

```sh
# Default: kv to stdout
stream ADDR

# CSV to file
stream ADDR -f csv -o data.csv

# Airbridge binary to UDP
stream ADDR -f airbridge -o udp:127.0.0.1:8025

# Classic DF2 at 3Hz to airbridge
--serial stream ADDR --df df2 -t collect -f airbridge -o udp:192.168.1.10:8025

# DF8 at 1Hz to airbridge
--serial stream ADDR --df df8 -f airbridge -o udp:127.0.0.1:8025

# CSV over UDP
stream ADDR -f csv -o udp:10.0.0.1:9000

# Custom format string
stream ADDR -f '{ts},{spo2},{pulse_rate}'

# Collect with extra fields
--serial stream ADDR --df df2 -t 'collect:spo2,pulse_rate,low_battery,smartpoint'

# Throttle DF2 raw output to 10Hz
--serial stream ADDR --df df2 -t throttle:10 -f csv
```
