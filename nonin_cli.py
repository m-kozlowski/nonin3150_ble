#!/usr/bin/env python3
import argparse
import asyncio
import json
import sys
from datetime import datetime

import nonin_lib


# Output formatters

def format_kv(stream: str, data: dict) -> str:
    ts = datetime.now().isoformat(timespec="milliseconds")
    parts = [f"ts={ts}", f"stream={stream}"]
    for k, v in _flatten(data).items():
        parts.append(f"{k}={v}")
    return " ".join(parts)


def format_csv_header(stream: str, data: dict) -> str:
    fields = ["ts", "stream"] + list(_flatten(data).keys())
    return ",".join(fields)


def format_csv(stream: str, data: dict) -> str:
    ts = datetime.now().isoformat(timespec="milliseconds")
    values = [ts, stream] + [str(v) for v in _flatten(data).values()]
    return ",".join(values)


def format_custom(fmt: str, stream: str, data: dict) -> str:
    flat = _flatten(data)
    flat["ts"] = datetime.now().isoformat(timespec="milliseconds")
    flat["stream"] = stream
    return fmt.format(**flat)


def _flatten(data: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in data.items():
        key = f"{prefix}{k}" if not prefix else f"{prefix}_{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        elif isinstance(v, list):
            out[key] = json.dumps(v)
        else:
            out[key] = v
    return out


# CLI commands

async def cmd_scan(args):
    seen = set()

    def on_found(address, name):
        if address not in seen:
            seen.add(address)
            print(f"  {address}  {name}")

    print("Scanning for Nonin devices... (Ctrl+C to stop)")
    await nonin_lib.scan_continuous(on_found)
    print(f"\n{len(seen)} device(s) found.")


async def cmd_stream(args):
    streams = [s.strip() for s in args.streams.split(",")]
    output = sys.stdout
    close_output = False

    if args.output:
        output = open(args.output, "w")
        close_output = True

    csv_header_printed = {}

    def on_data(stream: str, data: dict):
        if args.format:
            line = format_custom(args.format, stream, data)
        elif args.csv:
            if stream not in csv_header_printed:
                output.write(format_csv_header(stream, data) + "\n")
                csv_header_printed[stream] = True
            line = format_csv(stream, data)
        else:
            line = format_kv(stream, data)
        output.write(line + "\n")
        output.flush()

    client = nonin_lib.NoninClient(args.address)
    try:
        print(f"Connecting to {args.address}...", file=sys.stderr)
        await client.connect()
        print("Connected. Streaming... (Ctrl+C to stop)", file=sys.stderr)
        await client.subscribe(streams, on_data)
        while client.is_connected:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await client.disconnect()
        if close_output:
            output.close()


async def cmd_config(args):
    client = nonin_lib.NoninClient(args.address)
    try:
        await client.connect()
        await args.config_func(client, args)
    finally:
        await client.disconnect()


# Config sub-handlers

async def cfg_get_datetime(client, args):
    dt = await client.get_datetime()
    if args.raw:
        print(f"datetime={dt.isoformat()}")
    else:
        print(f"Device date/time: {dt.strftime('%Y-%m-%d %H:%M:%S')}")


async def cfg_set_datetime(client, args):
    if args.time:
        dt = datetime.fromisoformat(args.time)
    else:
        dt = datetime.now()
    await client.set_datetime(dt)
    if args.raw:
        print(f"datetime={dt.isoformat()}")
    else:
        print(f"Device date/time set to {dt.strftime('%Y-%m-%d %H:%M:%S')}")


async def cfg_get_activation(client, args):
    mode, name = await client.get_activation_mode()
    if args.raw:
        print(f"activation=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.ACTIVATION_MODE_DESC.get(mode, name)
        print(f"Activation mode: {desc}")


async def cfg_set_activation(client, args):
    mode = nonin_lib.resolve_activation_mode(args.mode)
    await client.set_activation_mode(mode)
    name = nonin_lib.ACTIVATION_MODES.get(mode, "?")
    if args.raw:
        print(f"activation=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.ACTIVATION_MODE_DESC.get(mode, name)
        print(f"Activation mode set: {desc}")


async def cfg_get_display(client, args):
    mode, name = await client.get_display_mode()
    if args.raw:
        print(f"display=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.DISPLAY_MODE_DESC.get(mode, name)
        print(f"Display mode: {desc}")


async def cfg_set_display(client, args):
    mode = nonin_lib.resolve_display_mode(args.mode)
    await client.set_display_mode(mode)
    name = nonin_lib.DISPLAY_MODES.get(mode, "?")
    if args.raw:
        print(f"display=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.DISPLAY_MODE_DESC.get(mode, name)
        print(f"Display mode set: {desc}")


async def cfg_get_storage_rate(client, args):
    rate, name = await client.get_storage_rate()
    if args.raw:
        print(f"storage_rate=0x{rate:02X} name={name}")
    else:
        desc = nonin_lib.STORAGE_RATE_DESC.get(rate, name)
        print(f"Storage rate: {desc}")


async def cfg_set_storage_rate(client, args):
    rate = nonin_lib.resolve_storage_rate(args.rate)
    await client.set_storage_rate(rate)
    name = nonin_lib.STORAGE_RATES.get(rate, "?")
    if args.raw:
        print(f"storage_rate=0x{rate:02X} name={name}")
    else:
        desc = nonin_lib.STORAGE_RATE_DESC.get(rate, name)
        print(f"Storage rate set: {desc}")


async def cfg_get_device_id(client, args):
    text = await client.get_device_id()
    if args.raw:
        print(f"device_id={text}")
    elif text:
        print(f"Device ID: {text}")
    else:
        print("Device ID: (not set)")


async def cfg_set_device_id(client, args):
    await client.set_device_id(args.text)
    if args.raw:
        print(f"device_id={args.text}")
    else:
        print(f"Device ID set to: {args.text}")


async def cfg_get_security(client, args):
    mode, name = await client.get_security_mode()
    if args.raw:
        print(f"security=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.SECURITY_MODE_DESC.get(mode, name)
        print(f"Security: {desc}")


async def cfg_set_security(client, args):
    mode = nonin_lib.resolve_security_mode(args.mode)
    await client.set_security_mode(mode)
    name = nonin_lib.SECURITY_MODES.get(mode, "?")
    if args.raw:
        print(f"security=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.SECURITY_MODE_DESC.get(mode, name)
        print(f"Security set: {desc}")


async def cfg_get_config(client, args):
    cfg = await client.get_config()
    if args.raw:
        for k, v in cfg.items():
            print(f"{k}={v}")
        return

    print("Device Configuration:")
    print(f"  Activation mode:  {cfg['activation_mode']}")
    print(f"  Storage rate:     {cfg['storage_rate']}")
    print(f"  Display mode:     {cfg['display_mode']}")
    if cfg.get("device_id"):
        print(f"  Device ID:        {cfg['device_id']}")
    else:
        print("  Device ID:        (not set)")

    print(f"  Software rev:     {cfg['software_revision']}")
    print(f"  Software date:    {cfg['software_revision_date']}")

    windows = []
    for i in range(1, 4):
        start = cfg[f"start_time_{i}"]
        stop = cfg[f"stop_time_{i}"]
        windows.append((i, start, stop))

    has_windows = any(s != t for _, s, t in windows)
    if has_windows:
        print("  Time windows:")
        for i, start, stop in windows:
            print(f"    Window {i}: {start} -> {stop}")
    else:
        print("  Time windows:     (none configured)")

    print(f"  Checksum valid:   {'yes' if cfg['checksum_valid'] else 'NO'}")


async def cfg_set_config(client, args):
    await client.set_config(
        activation_option=nonin_lib.resolve_activation_mode(args.activation),
        storage_rate=nonin_lib.resolve_storage_rate(args.storage_rate),
        display_option=nonin_lib.resolve_display_mode(args.display),
        start_time_1=args.start1,
        stop_time_1=args.stop1,
        start_time_2=args.start2,
        stop_time_2=args.stop2,
        start_time_3=args.start3,
        stop_time_3=args.stop3,
        device_id=args.device_id,
    )
    print("Configuration written.")


async def cfg_delete_bond(client, args):
    op = nonin_lib.resolve_delete_bond_op(args.operation)
    name = nonin_lib.DELETE_BOND_OPS.get(op, f"0x{op:02X}")
    await client.delete_bond(op)
    print(f"Bond(s) deleted ({name}).")


async def cfg_clear_memory(client, args):
    await client.clear_memory()
    print("Device memory cleared.")


async def cfg_turn_off_upon_disconnect(client, args):
    await client.turn_off_upon_disconnect()
    print("Turn-off-upon-disconnect enabled.")
    print("  (only effective in Bluetooth Connection activation mode)")


# Argument parser

EPILOG_STREAM = """\
output formats:
  default     key=value pairs: ts=... stream=oximetry spo2=98 pulse_rate=72 ...
  --csv       CSV with auto-printed header row
  --format    Python format string with field substitution

available streams:
  oximetry    SpO2, pulse rate, PAI, battery (1/s)
  df20        Pulse interval timing, up to 6 pulses/packet
  df22        Raw PPG waveform, 25 samples/packet (75 Hz)
  df23        Device status: sensor type, errors, battery %
  all         Subscribe to all streams

format string fields (oximetry):
  {spo2} {pulse_rate} {pai} {battery_voltage} {counter}
  {flags_encrypted} {flags_low_battery} {flags_sensor_attached}
  {flags_searching} {flags_smartpoint} {flags_weak_signal}
"""

EPILOG_CONFIG = """\
activation modes:
  sensor       Device turns on when sensor is connected. Turns off when sensor
               disconnects or after 10 minutes of invalid readings.
  programmed   Device turns on/off per configured time windows (requires sensor).
               Use set-config to define up to 3 start/stop time pairs.
  spot-check   Device turns on when a finger is inserted into the sensor.
               Turns off when finger is removed for 10s, sensor disconnects,
               or after 3 minutes of invalid readings.
  bluetooth    Device turns on when a BLE collector connects. Turns off when
               BLE disconnects (if no sensor or 10min invalid readings).
               Supports turn-off-upon-disconnect command for immediate shutdown.

display modes:
  full         SpO2, pulse rate, pulse bar graph, and battery all shown.
  partial      SpO2 and pulse rate hidden from the LCD display.
  mvi          Display always on. Shows stored data volume (hours:minutes)
               instead of SpO2/pulse rate. (Memory Volume Indicator)

storage rates:
  1s           1 sample/second,  max ~274 hours storage
  2s           1 sample/2 seconds, max ~548 hours storage
  4s           1 sample/4 seconds, max ~1097 hours storage (default)

security modes:
  mode1        Allows new BLE bonds during any connection.
  mode2        Allows new bonds only within 2 minutes of battery insertion.
               This is the default. The Bluetooth icon flashes during the
               bonding window. Window closes on first bond or connection.

bond operations:
  all                  Delete all stored bonds (max 7).
  current              Delete only the current collector's bond.
  all-except-current   Delete all bonds except the current collector's.

all values also accept hex (e.g. 0x31)
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="nonin_cli",
        description="Nonin WristOx2 3150 BLE command-line tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    sub.add_parser("scan",
                    help="Scan for Nonin BLE devices (continuous, Ctrl+C to stop)")

    # stream
    p_stream = sub.add_parser("stream",
                              help="Stream live sensor readings",
                              epilog=EPILOG_STREAM,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    p_stream.add_argument("address", help="Device MAC address")
    p_stream.add_argument("--streams", default="oximetry",
                          help="Comma-separated list (default: oximetry)")
    p_stream.add_argument("--format", dest="format", default=None,
                          help="Python format string, e.g. '{spo2},{pulse_rate}'")
    p_stream.add_argument("--csv", action="store_true",
                          help="Output as CSV with header")
    p_stream.add_argument("-o", "--output", default=None,
                          help="Write to file instead of stdout")

    # config
    p_cfg = sub.add_parser("config",
                           help="Read/write device configuration",
                           epilog=EPILOG_CONFIG,
                           formatter_class=argparse.RawDescriptionHelpFormatter)
    p_cfg.add_argument("address", help="Device MAC address")
    p_cfg.add_argument("--raw", action="store_true",
                       help="Output raw key=value pairs for scripting")
    cfg_sub = p_cfg.add_subparsers(dest="action", required=True)

    p = cfg_sub.add_parser("get-datetime", help="Read device clock")
    p.set_defaults(config_func=cfg_get_datetime)

    p = cfg_sub.add_parser("set-datetime", help="Set device clock (default: now)")
    p.add_argument("--time", default=None,
                   help="ISO format, e.g. '2026-03-30 14:30:00' (default: current time)")
    p.set_defaults(config_func=cfg_set_datetime)

    p = cfg_sub.add_parser("get-activation", help="Read activation mode")
    p.set_defaults(config_func=cfg_get_activation)

    p = cfg_sub.add_parser("set-activation",
                           help="Set activation mode (sensor|programmed|spot-check|bluetooth)")
    p.add_argument("mode",
                   help="sensor: on at sensor connect | programmed: per time windows | "
                        "spot-check: on at finger insert | bluetooth: on at BLE connect")
    p.set_defaults(config_func=cfg_set_activation)

    p = cfg_sub.add_parser("get-display", help="Read display mode")
    p.set_defaults(config_func=cfg_get_display)

    p = cfg_sub.add_parser("set-display", help="Set display mode (full|partial|mvi)")
    p.add_argument("mode",
                   help="full: all readings shown | partial: readings hidden | "
                        "mvi: always-on, shows memory usage")
    p.set_defaults(config_func=cfg_set_display)

    p = cfg_sub.add_parser("get-storage-rate", help="Read storage rate")
    p.set_defaults(config_func=cfg_get_storage_rate)

    p = cfg_sub.add_parser("set-storage-rate", help="Set storage rate (1s|2s|4s)")
    p.add_argument("rate",
                   help="1s: ~274h capacity | 2s: ~548h | 4s: ~1097h (default)")
    p.set_defaults(config_func=cfg_set_storage_rate)

    p = cfg_sub.add_parser("get-device-id", help="Read device identification string")
    p.set_defaults(config_func=cfg_get_device_id)

    p = cfg_sub.add_parser("set-device-id", help="Set device identification string")
    p.add_argument("text", help="ASCII string, max 50 characters")
    p.set_defaults(config_func=cfg_set_device_id)

    p = cfg_sub.add_parser("get-security", help="Read security mode")
    p.set_defaults(config_func=cfg_get_security)

    p = cfg_sub.add_parser("set-security", help="Set security mode (mode1|mode2)")
    p.add_argument("mode",
                   help="mode1: bonds anytime | mode2: bonds only within 2min of battery insert (default)")
    p.set_defaults(config_func=cfg_set_security)

    p = cfg_sub.add_parser("get-config", help="Read full device configuration")
    p.set_defaults(config_func=cfg_get_config)

    p = cfg_sub.add_parser("set-config", help="Write full configuration block")
    p.add_argument("--activation", required=True, help="sensor|programmed|spot-check|bluetooth")
    p.add_argument("--storage-rate", required=True, help="1s|2s|4s")
    p.add_argument("--display", required=True, help="full|partial|mvi")
    p.add_argument("--start1", required=True, help="Start time 1 (YYMMDDhhmm)")
    p.add_argument("--stop1", required=True, help="Stop time 1 (YYMMDDhhmm)")
    p.add_argument("--start2", required=True, help="Start time 2 (YYMMDDhhmm)")
    p.add_argument("--stop2", required=True, help="Stop time 2 (YYMMDDhhmm)")
    p.add_argument("--start3", required=True, help="Start time 3 (YYMMDDhhmm)")
    p.add_argument("--stop3", required=True, help="Stop time 3 (YYMMDDhhmm)")
    p.add_argument("--device-id", required=True, help="Device ID (max 50 ASCII chars)")
    p.set_defaults(config_func=cfg_set_config)

    p = cfg_sub.add_parser("delete-bond", help="Delete BLE bond(s)")
    p.add_argument("operation",
                   help="all: delete all bonds | current: only this collector | "
                        "all-except-current: keep only this collector")
    p.set_defaults(config_func=cfg_delete_bond)

    p = cfg_sub.add_parser("clear-memory", help="Erase all stored patient data")
    p.set_defaults(config_func=cfg_clear_memory)

    p = cfg_sub.add_parser("turn-off-upon-disconnect",
                           help="Turn off device when BLE disconnects (Bluetooth activation mode only)")
    p.set_defaults(config_func=cfg_turn_off_upon_disconnect)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "scan":
            asyncio.run(cmd_scan(args))
        elif args.command == "stream":
            asyncio.run(cmd_stream(args))
        elif args.command == "config":
            asyncio.run(cmd_config(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
