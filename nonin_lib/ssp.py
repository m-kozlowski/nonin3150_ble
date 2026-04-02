import glob
import socket
from datetime import datetime
from typing import Callable, Optional

from nonin_lib.common import (
    ACK, NAK,
    parse_datetime_payload, parse_activation_mode_payload,
    parse_display_mode_payload, parse_storage_rate_payload,
    parse_device_id_payload, parse_config_block_payload,
    parse_memory_data,
    parse_df2_packet, parse_df7_packet, parse_df8_packet, parse_df13_packet,
    build_set_data_format_command,
    build_serial_get_config_command, build_serial_set_config_command,
    build_serial_get_datetime_command, build_serial_set_datetime_command,
    build_serial_memory_playback_command, build_serial_cancel_playback_command,
    build_serial_clear_memory_command,
    encode_cfg_time_ascii_10,
    ACTIVATION_MODES, DISPLAY_MODES, STORAGE_RATES,
)

BTPROTO_RFCOMM = 3


def scan_serial() -> list:
    results = []
    for path in sorted(glob.glob("/dev/rfcomm*")):
        results.append({"port": path, "description": "rfcomm"})
    for path in sorted(glob.glob("/dev/ttyUSB*")) + sorted(glob.glob("/dev/ttyACM*")):
        results.append({"port": path, "description": "serial"})
    for path in sorted(glob.glob("/dev/cu.usbmodem*")) + sorted(glob.glob("/dev/cu.Nonin*")):
        results.append({"port": path, "description": "serial"})
    return results


class _SocketSerial:

    def __init__(self, sock: socket.socket, timeout: float):
        self._sock = sock
        self._timeout = timeout
        self._sock.settimeout(timeout)
        self.is_open = True

    def read(self, size: int) -> bytes:
        buf = bytearray()
        self._sock.settimeout(self._timeout)
        while len(buf) < size:
            try:
                chunk = self._sock.recv(size - len(buf))
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            self._sock.settimeout(0.5)
        return bytes(buf)

    def write(self, data: bytes) -> int:
        return self._sock.send(data)

    def flush(self):
        pass

    def reset_input_buffer(self):
        self._sock.setblocking(False)
        try:
            while self._sock.recv(4096):
                pass
        except (BlockingIOError, OSError):
            pass
        self._sock.setblocking(True)
        self._sock.settimeout(self._timeout)

    def close(self):
        self.is_open = False
        self._sock.close()

    @property
    def baudrate(self):
        return 9600

    @baudrate.setter
    def baudrate(self, value):
        pass


class NoninSerial:
    def __init__(self, port: str = None, address: str = None,
                 channel: int = 1, timeout: float = 2.0, connect_timeout: float = 15.0):

        self._port_path = port
        self._address = address
        self._channel = channel
        self._timeout = timeout
        self._connect_timeout = connect_timeout
        self._serial = None
        self._sock: Optional[socket.socket] = None

    def connect(self):
        if self._port_path:
            # Use pyserial for explicit port path
            import serial
            self._serial = serial.Serial(
                self._port_path,
                baudrate=9600,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=self._timeout,
            )
        elif self._address:
            # Connect via Bluetooth RFCOMM socket
            self._sock = socket.socket(
                socket.AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
            self._sock.settimeout(self._connect_timeout)
            self._sock.connect((self._address, self._channel))
            self._serial = _SocketSerial(self._sock, self._timeout)
        else:
            raise RuntimeError("No port or address specified")

    def disconnect(self):
        if self._serial:
            self._serial.close()
            self._serial = None
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    @property
    def is_connected(self) -> bool:
        return self._serial is not None and self._serial.is_open


    def _send_level2(self, cmd: bytes, retries: int = 3) -> bytes:

        import time
        for attempt in range(retries):
            self._serial.reset_input_buffer()
            self._serial.write(cmd)
            self._serial.flush()

            got_nak = False
            for _ in range(256):
                b = self._serial.read(1)
                if not b:
                    break
                if b[0] == ACK:
                    return b
                if b[0] == NAK:
                    got_nak = True
                    break

            if attempt < retries - 1:
                import sys
                what = "NAK" if got_nak else "no response"
                print(f"  {what}, retrying ({attempt + 1}/{retries})...",
                      file=sys.stderr)
                time.sleep(5)
                continue

            if got_nak:
                raise RuntimeError("Command rejected (NAK)")
            raise TimeoutError("No response from device")

    def _read_response(self, size: int) -> bytes:
        data = self._serial.read(size)
        if len(data) < size:
            raise TimeoutError(f"Short read: got {len(data)}, expected {size}")
        return data

    def _read_until_crlf(self) -> bytes:
        buf = bytearray()
        while True:
            b = self._serial.read(1)
            if not b:
                break
            buf.append(b[0])
            if buf.endswith(b"\r\n"):
                return bytes(buf[:-2])
        return bytes(buf)

    # Config API

    def get_datetime(self) -> datetime:
        self._send_level2(build_serial_get_datetime_command())
        data = self._read_response(12)
        self._serial.read(2)
        return parse_datetime_payload(data)

    def set_datetime(self, dt: Optional[datetime] = None):
        if dt is None:
            dt = datetime.now()
        self._send_level2(build_serial_set_datetime_command(dt))

    def get_config(self) -> dict:
        self._send_level2(build_serial_get_config_command())
        data = self._read_response(136)
        self._serial.read(2)
        return parse_config_block_payload(data)

    def set_config(self, **kwargs):
        from nonin_lib.common import build_set_configuration_command
        ble_frame = build_set_configuration_command(**kwargs)
        config_bytes = ble_frame[9:9 + 136]
        self._send_level2(build_serial_set_config_command(config_bytes))

    # Individual config accessors (read/write via full config block)

    def get_activation_mode(self) -> tuple:
        cfg = self.get_config()
        return cfg["activation_mode_raw"], cfg["activation_mode"]

    def set_activation_mode(self, mode: int):
        cfg = self.get_config()
        self._set_config_field(cfg, activation_option=mode)

    def get_display_mode(self) -> tuple:
        cfg = self.get_config()
        return cfg["display_mode_raw"], cfg["display_mode"]

    def set_display_mode(self, mode: int):
        cfg = self.get_config()
        self._set_config_field(cfg, display_option=mode)

    def get_storage_rate(self) -> tuple:
        cfg = self.get_config()
        return cfg["storage_rate_raw"], cfg["storage_rate"]

    def set_storage_rate(self, rate: int):
        cfg = self.get_config()
        self._set_config_field(cfg, storage_rate=rate)

    def get_device_id(self) -> str:
        cfg = self.get_config()
        return cfg["device_id"]

    def set_device_id(self, text: str):
        cfg = self.get_config()
        self._set_config_field(cfg, device_id=text)

    def _set_config_field(self, cfg, **overrides):
        raw = cfg["_raw"]
        buf = bytearray(raw)

        if "activation_option" in overrides:
            buf[2] = overrides["activation_option"]
        if "storage_rate" in overrides:
            buf[3] = overrides["storage_rate"]
        if "display_option" in overrides:
            buf[4] = overrides["display_option"]
        if "device_id" in overrides:
            did = overrides["device_id"].encode("ascii", errors="strict")
            if len(did) > 50:
                raise ValueError("Device ID must be <= 50 ASCII characters")
            buf[65:115] = did.ljust(50, b"\x00")

        checksum = sum(buf[0:134]) & 0xFFFF
        buf[134:136] = checksum.to_bytes(2, "big")

        self._send_level2(build_serial_set_config_command(bytes(buf)))

    def clear_memory(self):
        self._send_level2(build_serial_clear_memory_command())


    def download_memory(
        self,
        after: Optional[datetime] = None,
        before: Optional[datetime] = None,
        max_sessions: Optional[int] = None,
        skip_sessions: int = 0,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> list:
        """Download stored sessions. Switches to 38400 baud for playback."""
        self._send_level2(build_serial_memory_playback_command())

        self._serial.baudrate = 38400

        raw_chunks = []
        try:
            while True:
                chunk = self._serial.read(256)
                if not chunk:
                    break
                raw_chunks.append(chunk)
                if progress_callback:
                    total = sum(len(c) for c in raw_chunks)
                    progress_callback(total)

                # Check for early cancel
                if after or (max_sessions is not None):
                    raw = b"".join(raw_chunks)
                    sessions = parse_memory_data(raw)

                    should_cancel = False
                    if max_sessions is not None:
                        if len(sessions) >= skip_sessions + max_sessions:
                            should_cancel = True
                    if after:
                        for s in sessions:
                            if s["start_time"] and s["start_time"] < after:
                                should_cancel = True
                                break
                    if should_cancel:
                        # Cancel at playback baud rate
                        self._serial.write(build_serial_cancel_playback_command())
                        self._serial.flush()
                        import time
                        time.sleep(1)
                        break
        finally:
            self._serial.baudrate = 9600
            self._serial.reset_input_buffer()

        raw = b"".join(raw_chunks)
        sessions = parse_memory_data(raw)

        if after or before:
            sessions = [
                s for s in sessions
                if s["start_time"] is not None
                and (not after or s["start_time"] >= after)
                and (not before or s["start_time"] < before)
            ]

        if skip_sessions:
            sessions = sessions[skip_sessions:]

        if max_sessions is not None:
            sessions = sessions[:max_sessions]

        return sessions

    def cancel_memory_playback(self):
        self._serial.write(build_serial_cancel_playback_command())
        self._serial.flush()

    # Streaming

    def stream(self, data_format: int, callback: Callable[[str, dict], None]):
        """Set data format and stream parsed packets.

        data_format: 0x02 (DF2), 0x07 (DF7), 0x08 (DF8), 0x0D (DF13)
        callback(stream_name, parsed_dict) called for each packet.
        """
        self._serial.reset_input_buffer()
        cmd = build_set_data_format_command(data_format)
        self._serial.write(cmd)
        self._serial.flush()

        for _ in range(512):
            b = self._serial.read(1)
            if not b:
                raise RuntimeError("No response to data format command")
            if b[0] == ACK:
                break
            if b[0] == NAK:
                raise RuntimeError("Data format not accepted")
        else:
            raise RuntimeError("ACK not found after data format command")

        parser_map = {
            0x02: ("df2", parse_df2_packet, 5),
            0x07: ("df7", parse_df7_packet, 4),
            0x08: ("df8", parse_df8_packet, 4),
            0x0D: ("df13", parse_df13_packet, 4),
        }

        stream_name, parser, packet_size = parser_map[data_format]

        # DF2: byte 1 = 0x01 (start byte). DF7/DF8: byte 1 = STATUS (bit 7 set).
        if data_format == 0x02:
            sync_val = 0x01
            sync_mask = 0xFF
        else:
            sync_val = 0x80
            sync_mask = 0x80

        synced = False

        while self._serial.is_open:
            if not synced:
                b = self._serial.read(1)
                if not b:
                    continue
                if b[0] & sync_mask == sync_val:
                    rest = self._serial.read(packet_size - 1)
                    if len(rest) == packet_size - 1:
                        frame = bytes([b[0]]) + rest
                        parsed = parser(frame)
                        if parsed:
                            callback(stream_name, parsed)
                            synced = True
                continue

            data = self._serial.read(packet_size)
            if len(data) < packet_size:
                continue
            if data[0] & sync_mask != sync_val:
                synced = False
                continue
            parsed = parser(data)
            if parsed:
                callback(stream_name, parsed)
