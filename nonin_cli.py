#!/usr/bin/env python3
import argparse
import asyncio
import json
import sys
from datetime import datetime

import nonin_lib.common as nonin_lib
import nonin_lib.ble as nonin_ble
import nonin_lib.ssp as nonin_serial


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
    if args.serial:
        ports = nonin_serial.scan_serial()
        if not ports:
            print("No serial ports found.")
        else:
            for p in ports:
                print(f"  {p['port']}  ({p['description']})")
        return

    seen = set()

    def on_found(address, name):
        if address not in seen:
            seen.add(address)
            print(f"  {address}  {name}")

    print("Scanning for Nonin BLE devices... (Ctrl+C to stop)")
    await nonin_ble.scan_continuous(on_found)
    print(f"\n{len(seen)} device(s) found.")


async def cmd_stream(args):
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

    try:
        if args.serial:
            client = nonin_serial.NoninSerial(port=args.port, address=args.address)
            client.connect()
            print(f"Connected. Streaming {args.df}... (Ctrl+C to stop)", file=sys.stderr)
            df = nonin_lib.resolve_data_format(args.df)
            try:
                client.stream(df, on_data)
            except KeyboardInterrupt:
                pass
            finally:
                client.disconnect()
        else:
            streams = [s.strip() for s in args.streams.split(",")]
            client = nonin_ble.NoninBLE(args.address)
            print(f"Connecting to {args.address}...", file=sys.stderr)
            await client.connect()
            print("Connected. Streaming... (Ctrl+C to stop)", file=sys.stderr)
            await client.subscribe(streams, on_data)
            try:
                while client.is_connected:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                await client.disconnect()
    finally:
        if close_output:
            output.close()


async def cmd_download(args):
    output = sys.stdout
    close_output = False

    if args.output:
        output = open(args.output, "w")
        close_output = True

    after = datetime.fromisoformat(args.after) if args.after else None
    before = datetime.fromisoformat(args.before) if args.before else None
    max_sessions = args.first if args.first else None
    skip_sessions = args.skip if args.skip else 0

    def on_progress(byte_count):
        print(f"\r  Received {byte_count} bytes...", end="", file=sys.stderr)

    try:
        if args.serial:
            client = nonin_serial.NoninSerial(port=args.port, address=args.address)
            client.connect()
            print("Downloading stored records...", file=sys.stderr)
            sessions = client.download_memory(
                after=after, before=before,
                max_sessions=max_sessions, skip_sessions=skip_sessions,
                progress_callback=on_progress)
            print(f"\n  {len(sessions)} session(s) downloaded.", file=sys.stderr)
            client.disconnect()
        else:
            client = nonin_ble.NoninBLE(args.address)
            print(f"Connecting to {args.address}...", file=sys.stderr)
            await client.connect()
            print("Downloading stored records...", file=sys.stderr)
            sessions = await client.download_memory(
                after=after, before=before,
                max_sessions=max_sessions, skip_sessions=skip_sessions,
                progress_callback=on_progress)
            print(f"\n  {len(sessions)} session(s) downloaded.", file=sys.stderr)
            await client.disconnect()

        if not sessions:
            print("No stored sessions found.", file=sys.stderr)
            return

        if args.csv:
            output.write("session,sample,timestamp,spo2,pulse_rate\n")
            for si, session in enumerate(sessions):
                interval = session["seconds_per_sample"]
                start = session["start_time"]
                for ji, (spo2, pr) in enumerate(session["samples"]):
                    if start:
                        from datetime import timedelta
                        ts = (start + timedelta(seconds=ji * interval)).isoformat()
                    else:
                        ts = str(ji * interval)
                    spo2_s = "" if spo2 is None else str(spo2)
                    pr_s = "" if pr is None else str(pr)
                    output.write(f"{si},{ji},{ts},{spo2_s},{pr_s}\n")
        elif args.raw:
            for si, session in enumerate(sessions):
                output.write(f"session={si}\n")
                output.write(f"seconds_per_sample={session['seconds_per_sample']}\n")
                output.write(f"start_time={session['start_time'].isoformat() if session['start_time'] else ''}\n")
                output.write(f"stop_time={session['stop_time'].isoformat() if session['stop_time'] else ''}\n")
                output.write(f"samples={len(session['samples'])}\n")
                for spo2, pr in session["samples"]:
                    spo2_s = "" if spo2 is None else str(spo2)
                    pr_s = "" if pr is None else str(pr)
                    output.write(f"{spo2_s},{pr_s}\n")
                output.write("\n")
        else:
            for si, session in enumerate(sessions):
                start = session["start_time"]
                stop = session["stop_time"]
                n = len(session["samples"])
                interval = session["seconds_per_sample"]
                start_s = start.strftime("%Y-%m-%d %H:%M:%S") if start else "unknown"
                stop_s = stop.strftime("%Y-%m-%d %H:%M:%S") if stop else "unknown"

                valid = [(s, p) for s, p in session["samples"] if s is not None]
                if valid:
                    spo2_vals = [s for s, _ in valid]
                    pr_vals = [p for _, p in valid if p is not None]
                    spo2_avg = sum(spo2_vals) / len(spo2_vals)
                    pr_avg = sum(pr_vals) / len(pr_vals) if pr_vals else 0
                    spo2_min = min(spo2_vals)
                    spo2_max = max(spo2_vals)
                else:
                    spo2_avg = spo2_min = spo2_max = pr_avg = 0

                print(f"Session {si + 1}:")
                print(f"  Start:    {start_s}")
                print(f"  Stop:     {stop_s}")
                print(f"  Interval: {interval}s")
                print(f"  Samples:  {n}")
                if valid:
                    print(f"  SpO2:     avg={spo2_avg:.0f} min={spo2_min} max={spo2_max}")
                    print(f"  PR:       avg={pr_avg:.0f}")
                print()

        output.flush()
    finally:
        if close_output:
            output.close()


async def cmd_config(args):
    if args.serial:
        if args.action in BLE_ONLY_COMMANDS:
            print(f"Error: '{args.action}' is only available over BLE, not serial.", file=sys.stderr)
            return
        client = nonin_serial.NoninSerial(port=args.port, address=args.address)
        try:
            client.connect()
            result = args.config_func(client, args)
            if asyncio.iscoroutine(result):
                await result
        finally:
            client.disconnect()
    else:
        client = nonin_ble.NoninBLE(args.address)
        try:
            await client.connect()
            await args.config_func(client, args)
        finally:
            await client.disconnect()


# Config sub-handlers
# These use `await` on client methods. For BLE, methods are async coroutines.
# For serial, methods return plain values. We use _call() to handle both.

async def _call(method, *args, **kwargs):
    result = method(*args, **kwargs)
    if asyncio.iscoroutine(result):
        return await result
    return result

BLE_ONLY_COMMANDS = {
    "get-security", "set-security", "delete-bond", "turn-off-upon-disconnect",
}

async def cfg_get_datetime(client, args):
    dt = await _call(client.get_datetime)
    if args.raw:
        print(f"datetime={dt.isoformat()}")
    else:
        print(f"Device date/time: {dt.strftime('%Y-%m-%d %H:%M:%S')}")


async def cfg_set_datetime(client, args):
    if args.time:
        dt = datetime.fromisoformat(args.time)
    else:
        dt = datetime.now()
    await _call(client.set_datetime, dt)
    if args.raw:
        print(f"datetime={dt.isoformat()}")
    else:
        print(f"Device date/time set to {dt.strftime('%Y-%m-%d %H:%M:%S')}")


async def cfg_get_activation(client, args):
    mode, name = await _call(client.get_activation_mode)
    if args.raw:
        print(f"activation=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.ACTIVATION_MODE_DESC.get(mode, name)
        print(f"Activation mode: {desc}")


async def cfg_set_activation(client, args):
    mode = nonin_lib.resolve_activation_mode(args.mode)
    await _call(client.set_activation_mode, mode)
    name = nonin_lib.ACTIVATION_MODES.get(mode, "?")
    if args.raw:
        print(f"activation=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.ACTIVATION_MODE_DESC.get(mode, name)
        print(f"Activation mode set: {desc}")


async def cfg_get_display(client, args):
    mode, name = await _call(client.get_display_mode)
    if args.raw:
        print(f"display=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.DISPLAY_MODE_DESC.get(mode, name)
        print(f"Display mode: {desc}")


async def cfg_set_display(client, args):
    mode = nonin_lib.resolve_display_mode(args.mode)
    await _call(client.set_display_mode, mode)
    name = nonin_lib.DISPLAY_MODES.get(mode, "?")
    if args.raw:
        print(f"display=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.DISPLAY_MODE_DESC.get(mode, name)
        print(f"Display mode set: {desc}")


async def cfg_get_storage_rate(client, args):
    rate, name = await _call(client.get_storage_rate)
    if args.raw:
        print(f"storage_rate=0x{rate:02X} name={name}")
    else:
        desc = nonin_lib.STORAGE_RATE_DESC.get(rate, name)
        print(f"Storage rate: {desc}")


async def cfg_set_storage_rate(client, args):
    rate = nonin_lib.resolve_storage_rate(args.rate)
    await _call(client.set_storage_rate, rate)
    name = nonin_lib.STORAGE_RATES.get(rate, "?")
    if args.raw:
        print(f"storage_rate=0x{rate:02X} name={name}")
    else:
        desc = nonin_lib.STORAGE_RATE_DESC.get(rate, name)
        print(f"Storage rate set: {desc}")


async def cfg_get_device_id(client, args):
    text = await _call(client.get_device_id)
    if args.raw:
        print(f"device_id={text}")
    elif text:
        print(f"Device ID: {text}")
    else:
        print("Device ID: (not set)")


async def cfg_set_device_id(client, args):
    await _call(client.set_device_id, args.text)
    if args.raw:
        print(f"device_id={args.text}")
    else:
        print(f"Device ID set to: {args.text}")


async def cfg_get_security(client, args):
    mode, name = await _call(client.get_security_mode)
    if args.raw:
        print(f"security=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.SECURITY_MODE_DESC.get(mode, name)
        print(f"Security: {desc}")


async def cfg_set_security(client, args):
    mode = nonin_lib.resolve_security_mode(args.mode)
    await _call(client.set_security_mode, mode)
    name = nonin_lib.SECURITY_MODES.get(mode, "?")
    if args.raw:
        print(f"security=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.SECURITY_MODE_DESC.get(mode, name)
        print(f"Security set: {desc}")


async def cfg_get_config(client, args):
    cfg = await _call(client.get_config)
    if args.raw:
        for k, v in cfg.items():
            if k.startswith("_"):
                continue
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
    await _call(client.set_config,
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
    await _call(client.delete_bond, op)
    print(f"Bond(s) deleted ({name}).")


async def cfg_clear_memory(client, args):
    await _call(client.clear_memory)
    print("Device memory cleared.")


async def cfg_turn_off_upon_disconnect(client, args):
    await _call(client.turn_off_upon_disconnect)
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
        description="Nonin WristOx2 3150 BLE/Classic command-line tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--serial", action="store_true",
                        help="Use serial/SPP transport instead of BLE")
    parser.add_argument("--port", default=None,
                        help="Serial port path (e.g. /dev/rfcomm0). "
                             "If not given, auto-binds rfcomm from the device address.")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    sub.add_parser("scan",
                    help="Scan for devices (BLE by default, serial ports with --serial)")

    # stream
    p_stream = sub.add_parser("stream",
                              help="Stream live sensor readings",
                              epilog=EPILOG_STREAM,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    p_stream.add_argument("address", help="Device MAC address")
    p_stream.add_argument("--streams", default="oximetry",
                          help="BLE: comma-separated list (default: oximetry)")
    p_stream.add_argument("--df", default="df8",
                          help="Serial: data format - df2 (75Hz), df7 (75Hz 16-bit), "
                               "df8 (1Hz), df13 (spot-check). Default: df8")
    p_stream.add_argument("--format", dest="format", default=None,
                          help="Python format string, e.g. '{spo2},{pulse_rate}'")
    p_stream.add_argument("--csv", action="store_true",
                          help="Output as CSV with header")
    p_stream.add_argument("-o", "--output", default=None,
                          help="Write to file instead of stdout")

    # download
    p_dl = sub.add_parser("download",
                           help="Download stored sessions from device memory",
                           formatter_class=argparse.RawDescriptionHelpFormatter,
                           epilog="""\
output formats:
  default     Session summary with averages and min/max
  --csv       CSV: session,sample,timestamp,spo2,pulse_rate
  --raw       Key=value headers + raw spo2,pr per line

Sessions are returned newest first. Timestamps are based on the
device clock (set with: config <addr> set-datetime).
""")
    p_dl.add_argument("address", help="Device MAC address")
    p_dl.add_argument("--after", default=None,
                       help="Only sessions starting at or after this time (ISO format). "
                            "Cancels download early once older sessions are reached.")
    p_dl.add_argument("--before", default=None,
                       help="Only sessions starting before this time (ISO format)")
    p_dl.add_argument("--first", type=int, default=None,
                       help="Download only the N most recent sessions, then cancel")
    p_dl.add_argument("--skip", type=int, default=0,
                       help="Skip the first N sessions (newest)")
    p_dl.add_argument("--csv", action="store_true", help="Output as CSV")
    p_dl.add_argument("--raw", action="store_true", help="Raw key=value output")
    p_dl.add_argument("-o", "--output", default=None, help="Write to file instead of stdout")

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
        elif args.command == "download":
            asyncio.run(cmd_download(args))
        elif args.command == "config":
            asyncio.run(cmd_config(args))
    except KeyboardInterrupt:
        pass
    except (OSError, RuntimeError, TimeoutError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
