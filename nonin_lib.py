import asyncio
import sys
from datetime import datetime
from typing import Callable, Optional

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData


# BLE UUIDs

NONIN_SERVICE_UUID = "46A970E0-0D5F-11E2-8B5E-0002A5D5C51B"
CONTINUOUS_OXIM_UUID = "0AAD7EA0-0D60-11E2-8E3C-0002A5D5C51B"
CONTROL_POINT_UUID = "1447AF80-0D60-11E2-88B6-0002A5D5C51B"
DEVICE_STATUS_DF23_UUID = "EC0A9302-4D24-11E7-B114-B2F933D5FE66"
PULSE_INTERVAL_DF20_UUID = "34E27863-76FF-4F8E-96F1-9E3993AA6199"
PPG_DF22_UUID = "EC0A883A-4D24-11E7-B114-B2F933D5FE66"


# Lookup tables

STORAGE_RATES = {
    0x31: "1s",
    0x32: "2s",
    0x34: "4s",
}

STORAGE_RATE_DESC = {
    0x31: "1 second/sample  (max ~274 hours storage)",
    0x32: "2 seconds/sample (max ~548 hours storage)",
    0x34: "4 seconds/sample (max ~1097 hours storage)",
}

STORAGE_RATE_NAMES = {v: k for k, v in STORAGE_RATES.items()}

DF22_EXPECTED_LENGTH = 53

DF23_SENSOR_TYPES = {
    0x01: "Pulse Oximeter Sensor",
}

DF23_ERRORS = {
    0x00: "No error",
    0x01: "No sensor",
    0x05: "Sensor fault",
    0x06: "System error",
}

ACTIVATION_MODES = {
    0x31: "sensor",
    0x32: "programmed",
    0x33: "spot-check",
    0x34: "bluetooth",
}

ACTIVATION_MODE_DESC = {
    0x31: "Sensor        - turns on when sensor connected, off when disconnected or 10min invalid",
    0x32: "Programmed    - turns on/off per configured time windows while sensor connected",
    0x33: "Spot-Check    - turns on at finger insertion, off at removal (10s) or 3min invalid",
    0x34: "Bluetooth     - turns on at BLE connection, off at disconnect (if no sensor/10min invalid)",
}

ACTIVATION_MODE_NAMES = {v: k for k, v in ACTIVATION_MODES.items()}

SECURITY_MODES = {
    0x01: "mode1",
    0x02: "mode2",
}

SECURITY_MODE_DESC = {
    0x01: "Mode 1 - allows new bonds during each connection (no battery pull needed)",
    0x02: "Mode 2 - allows new bonds only within 2 min of battery insertion (default)",
}

SECURITY_MODE_NAMES = {v: k for k, v in SECURITY_MODES.items()}

DISPLAY_MODES = {
    0x31: "full",
    0x32: "partial",
    0x33: "mvi",
}

DISPLAY_MODE_DESC = {
    0x31: "Full    - SpO2, PR, pulse bar, battery status all shown",
    0x32: "Partial - SpO2 and PR hidden from display",
    0x33: "MVI     - display always on, shows memory usage instead of readings",
}

DISPLAY_MODE_NAMES = {v: k for k, v in DISPLAY_MODES.items()}

DELETE_BOND_OPS = {
    0x00: "all",
    0x01: "current",
    0x02: "all-except-current",
}

DELETE_BOND_OP_NAMES = {v: k for k, v in DELETE_BOND_OPS.items()}


# Parsers

def parse_continuous_oximetry(data: bytearray) -> dict:
    status = data[1]
    batt_voltage = data[2] * 0.1
    pai = ((data[3] << 8) | data[4]) / 100.0
    counter = (data[5] << 8) | data[6]
    spo2 = None if data[7] == 127 else data[7]
    pr_raw = (data[8] << 8) | data[9]
    pulse_rate = None if pr_raw == 511 else pr_raw

    flags = {
        "encrypted": bool(status & (1 << 6)),
        "low_battery": bool(status & (1 << 5)),
        "sensor_attached": bool(status & (1 << 4)),
        "searching": bool(status & (1 << 3)),
        "smartpoint": bool(status & (1 << 2)),
        "weak_signal": bool(status & (1 << 1)),
    }

    return {
        "battery_voltage": batt_voltage,
        "pai": pai,
        "counter": counter,
        "spo2": spo2,
        "pulse_rate": pulse_rate,
        "flags": flags,
    }


def parse_df20_pulse_field(raw: bytes) -> dict:
    if len(raw) != 4:
        raise ValueError("Pulse field must be exactly 4 bytes")
    status_mso = raw[0]
    pai_lso = raw[1]
    pulse_time = int.from_bytes(raw[2:4], "big")
    bad_pulse = bool(status_mso & 0x80)
    pai_mso = status_mso & 0x0F
    pai_raw = (pai_mso << 8) | pai_lso
    pai_pct = pai_raw / 100.0
    return {
        "bad_pulse": bad_pulse,
        "pai_raw": pai_raw,
        "pai_percent": pai_pct,
        "pulse_interval_ms": pulse_time * 0.1,
    }


def parse_df20_payload(payload: bytes) -> dict:
    if len(payload) < 4:
        raise ValueError(f"DF20 frame too short: {len(payload)} bytes")
    pkt_len = payload[0]
    if pkt_len != len(payload):
        raise ValueError(f"DF20 length mismatch: header={pkt_len}, actual={len(payload)}")
    counter = int.from_bytes(payload[1:3], "big")
    status = payload[3]
    invalid_signal = bool(status & 0x01)
    pulse_rate_too_high = bool(status & 0x02)
    pulses = []
    if not (invalid_signal or pulse_rate_too_high):
        offset = 4
        while offset + 4 <= len(payload) and len(pulses) < 6:
            pulse_raw = payload[offset:offset + 4]
            pulses.append(parse_df20_pulse_field(pulse_raw))
            offset += 4
    return {
        "packet_length": pkt_len,
        "counter": counter,
        "status_raw": status,
        "invalid_signal": invalid_signal,
        "pulse_rate_too_high": pulse_rate_too_high,
        "pulses": pulses,
        "pulse_count": len(pulses),
    }


def parse_df22_payload(payload: bytes) -> dict:
    if len(payload) != DF22_EXPECTED_LENGTH:
        raise ValueError(f"DF22 invalid length: {len(payload)} (expected {DF22_EXPECTED_LENGTH})")
    pkt_len = payload[0]
    if pkt_len != len(payload):
        raise ValueError(f"DF22 length mismatch: header={pkt_len}, actual={len(payload)}")
    ppg_samples = []
    offset = 1
    for _ in range(25):
        sample = int.from_bytes(payload[offset:offset + 2], "big", signed=False)
        ppg_samples.append(sample)
        offset += 2
    counter = int.from_bytes(payload[offset:offset + 2], "big")
    return {
        "packet_length": pkt_len,
        "ppg_samples": ppg_samples,
        "counter": counter,
    }


def parse_df23_payload(payload: bytes) -> dict:
    if len(payload) < 7:
        raise ValueError(f"DF23 frame too short: {len(payload)} bytes")
    pkt_len = payload[0]
    if pkt_len != len(payload):
        raise ValueError(f"DF23 length mismatch: header={pkt_len}, actual={len(payload)}")
    sensor_type = payload[1]
    error_code = payload[2]
    batt_volt = payload[3]
    batt_pct = payload[4]
    tx_index = int.from_bytes(payload[5:7], "big")
    return {
        "packet_length": pkt_len,
        "sensor_type_raw": sensor_type,
        "sensor_type": DF23_SENSOR_TYPES.get(sensor_type, f"Unknown(0x{sensor_type:02X})"),
        "error_raw": error_code,
        "error": DF23_ERRORS.get(error_code, f"Unknown(0x{error_code:02X})"),
        "battery_voltage_raw": batt_volt,
        "battery_percentage": batt_pct,
        "tx_index": tx_index,
    }


def parse_datetime_payload(payload: bytes) -> datetime:
    year = int(payload[0:2].decode())
    month = int(payload[2:4].decode())
    day = int(payload[4:6].decode())
    hour = int(payload[6:8].decode())
    minute = int(payload[8:10].decode())
    second = int(payload[10:12].decode())
    return datetime(2000 + year, month, day, hour, minute, second)


def parse_activation_mode_payload(payload: bytes) -> tuple:
    mode = payload[0]
    return mode, ACTIVATION_MODES.get(mode, f"Unknown(0x{mode:02X})")


def parse_turn_off_upon_disconnect_payload(payload: bytes) -> bool:
    if payload[0] == 0x06:
        return True
    if payload[0] == 0x15:
        return False
    raise ValueError("Invalid TOUD ACK")


def parse_security_mode_response_byte(mode_byte: int) -> tuple:
    name = SECURITY_MODES.get(mode_byte, f"Unknown(0x{mode_byte:02X})")
    return mode_byte, name


def parse_display_mode_payload(payload: bytes) -> tuple:
    if len(payload) != 1:
        raise ValueError("Invalid Display Mode payload length")
    mode = payload[0]
    name = DISPLAY_MODES.get(mode, f"Unknown(0x{mode:02X})")
    return mode, name


def parse_device_id_payload(payload: bytes) -> str:
    if len(payload) != 50:
        raise ValueError("Invalid Device ID payload length")
    return payload.rstrip(b"\x00").decode("ascii", errors="strict")


def parse_cfg_time_ascii_10(raw: bytes) -> str:
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return raw.hex()


def encode_cfg_time_ascii_10(timestr: str) -> bytes:
    if len(timestr) != 10 or not timestr.isdigit():
        raise ValueError("Time must be in 'YYMMDDhhmm' format")
    return timestr.encode("ascii")


def _decode_ascii_or_hex(raw: bytes) -> str:
    stripped = raw.rstrip(b"\x00")
    if not stripped:
        return ""
    try:
        return stripped.decode("ascii")
    except UnicodeDecodeError:
        return raw.hex()


def _format_cfg_time(raw_str: str) -> str:
    if len(raw_str) == 10 and raw_str.isdigit():
        return f"20{raw_str[0:2]}-{raw_str[2:4]}-{raw_str[4:6]} {raw_str[6:8]}:{raw_str[8:10]}"
    return raw_str


def parse_config_block_payload(payload: bytes) -> dict:
    if len(payload) != 136:
        raise ValueError(f"Invalid CFG payload length: {len(payload)}")
    cfg = {}
    cfg["activation_mode"] = ACTIVATION_MODES.get(payload[2], f"unknown(0x{payload[2]:02X})")
    cfg["activation_mode_raw"] = payload[2]
    cfg["storage_rate"] = STORAGE_RATES.get(payload[3], f"unknown(0x{payload[3]:02X})")
    cfg["storage_rate_raw"] = payload[3]
    cfg["display_mode"] = DISPLAY_MODES.get(payload[4], f"unknown(0x{payload[4]:02X})")
    cfg["display_mode_raw"] = payload[4]

    raw_times = {}
    raw_times["start_time_1"] = parse_cfg_time_ascii_10(payload[5:15])
    raw_times["stop_time_1"] = parse_cfg_time_ascii_10(payload[15:25])
    raw_times["start_time_2"] = parse_cfg_time_ascii_10(payload[25:35])
    raw_times["stop_time_2"] = parse_cfg_time_ascii_10(payload[35:45])
    raw_times["start_time_3"] = parse_cfg_time_ascii_10(payload[45:55])
    raw_times["stop_time_3"] = parse_cfg_time_ascii_10(payload[55:65])
    for k, v in raw_times.items():
        cfg[k] = _format_cfg_time(v)
        cfg[k + "_raw"] = v

    cfg["device_id"] = payload[65:115].rstrip(b"\x00").decode("ascii", "replace")
    cfg["software_revision"] = _decode_ascii_or_hex(payload[119:122])
    cfg["software_revision_date"] = _decode_ascii_or_hex(payload[122:128])

    cfg["checksum"] = int.from_bytes(payload[134:136], "big")
    checksum_calc = sum(payload[0:134]) & 0xFFFF
    cfg["checksum_valid"] = checksum_calc == cfg["checksum"]
    return cfg


def parse_storage_rate_payload(payload: bytes) -> tuple:
    if len(payload) != 1:
        raise ValueError("Invalid Storage Rate payload length")
    rate = payload[0]
    name = STORAGE_RATES.get(rate, f"Unknown(0x{rate:02X})")
    return rate, name


# Command builders

def build_get_datetime_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x44, 0x54, 0x4D, 0x3F, 0x0D, 0x0A])


def build_set_datetime_command(dt: datetime):
    ts = dt.strftime("%y%m%d%H%M%S").encode()
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x12, 0x44, 0x54, 0x4D, 0x3D]) + ts + bytes([0x0D, 0x0A])


def build_get_activation_mode_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x41, 0x43, 0x54, 0x3F, 0x0D, 0x0A])


def build_set_activation_mode_command(mode: int):
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x07, 0x41, 0x43, 0x54, 0x3D, mode, 0x0D, 0x0A])


def build_turn_off_upon_disconnect_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x54, 0x4F, 0x46, 0x21, 0x0D, 0x0A])


def build_get_security_mode_command():
    return bytes([0x65, 0x4E, 0x4D, 0x49])


def build_set_security_mode_command(mode: int):
    if mode not in SECURITY_MODES:
        raise ValueError(f"Invalid security mode: 0x{mode:02X}")
    return bytes([0x64, 0x4E, 0x4D, 0x49, mode])


def build_set_display_mode_command(mode: int):
    if mode not in DISPLAY_MODES:
        raise ValueError(f"Invalid display mode: 0x{mode:02X}")
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x07, 0x44, 0x49, 0x53, 0x3D, mode, 0x0D, 0x0A])


def build_get_display_mode_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x44, 0x49, 0x53, 0x3F, 0x0D, 0x0A])


def build_set_device_id_command(text: str):
    raw = text.encode("ascii", errors="strict")
    if len(raw) > 50:
        raise ValueError("Device ID string must be <= 50 ASCII characters")
    padded = raw.ljust(50, b'\x00')
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x38, 0x49, 0x44, 0x53, 0x3D]) + padded + bytes([0x0D, 0x0A])


def build_get_device_id_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x49, 0x44, 0x53, 0x3F, 0x0D, 0x0A])


def build_get_config_block_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x43, 0x46, 0x47, 0x3F, 0x0D, 0x0A])


def build_set_configuration_command(
    *,
    activation_option: int,
    storage_rate: int,
    display_option: int,
    start_time_1: str,
    stop_time_1: str,
    start_time_2: str,
    stop_time_2: str,
    start_time_3: str,
    stop_time_3: str,
    device_id: str,
):
    payload = bytearray(136)
    payload[0:2] = b"\x00\x00"
    payload[2] = activation_option
    payload[3] = storage_rate
    payload[4] = display_option
    payload[5:15] = encode_cfg_time_ascii_10(start_time_1)
    payload[15:25] = encode_cfg_time_ascii_10(stop_time_1)
    payload[25:35] = encode_cfg_time_ascii_10(start_time_2)
    payload[35:45] = encode_cfg_time_ascii_10(stop_time_2)
    payload[45:55] = encode_cfg_time_ascii_10(start_time_3)
    payload[55:65] = encode_cfg_time_ascii_10(stop_time_3)
    raw_id = device_id.encode("ascii", errors="strict")
    if len(raw_id) > 50:
        raise ValueError("Device ID must be <= 50 ASCII characters")
    payload[65:115] = raw_id.ljust(50, b"\x00")
    payload[115:119] = b"\x00" * 4
    payload[119:122] = b"\x00\x00\x00"
    payload[122:128] = b"\x00" * 6
    payload[128:134] = b"\x00" * 6
    checksum = sum(payload[0:134]) & 0xFFFF
    payload[134:136] = checksum.to_bytes(2, "big")
    frame = bytes([0x60, 0x4E, 0x4D, 0x49, 0x8D, 0x43, 0x46, 0x47, 0x3D]) + payload + bytes([0x0D, 0x0A])
    if len(frame) != 147:
        raise RuntimeError(f"SET_CONFIGURATION frame size is {len(frame)}, expected 147")
    return frame


def build_delete_bond_command(operation: int):
    if operation not in DELETE_BOND_OPS:
        raise ValueError(f"Invalid delete bond operation: 0x{operation:02X}")
    return bytes([0x63, 0x4E, 0x4D, 0x49, operation])


def build_clear_memory_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x4D, 0x43, 0x4C, 0x21, 0x0D, 0x0A])


def build_set_storage_rate_command(rate: int):
    if rate not in STORAGE_RATES:
        raise ValueError(f"Invalid storage rate: 0x{rate:02X}")
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x07, 0x44, 0x53, 0x52, 0x3D, rate, 0x0D, 0x0A])


def build_get_storage_rate_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x44, 0x53, 0x52, 0x3F, 0x0D, 0x0A])


# Name resolution helpers

def resolve_activation_mode(value: str) -> int:
    if value in ACTIVATION_MODE_NAMES:
        return ACTIVATION_MODE_NAMES[value]
    return int(value, 0)


def resolve_display_mode(value: str) -> int:
    if value in DISPLAY_MODE_NAMES:
        return DISPLAY_MODE_NAMES[value]
    return int(value, 0)


def resolve_storage_rate(value: str) -> int:
    if value in STORAGE_RATE_NAMES:
        return STORAGE_RATE_NAMES[value]
    return int(value, 0)


def resolve_security_mode(value: str) -> int:
    if value in SECURITY_MODE_NAMES:
        return SECURITY_MODE_NAMES[value]
    return int(value, 0)


def resolve_delete_bond_op(value: str) -> int:
    if value in DELETE_BOND_OP_NAMES:
        return DELETE_BOND_OP_NAMES[value]
    return int(value, 0)


# Scanner

def _is_nonin(device: BLEDevice, adv: AdvertisementData) -> bool:
    nonin_lower = NONIN_SERVICE_UUID.lower()
    return any(u.lower() == nonin_lower for u in (adv.service_uuids or []))


async def scan_continuous(callback: Callable[[str, str], None]):
    scanner = BleakScanner(detection_callback=lambda d, a: (
        callback(d.address, d.name or "Unknown") if _is_nonin(d, a) else None
    ))
    await scanner.start()
    try:
        while True:
            await asyncio.sleep(1)
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        await scanner.stop()


# High-level async client

class NoninClient:
    def __init__(self, address: str, timeout: float = 30.0):
        self.address = address
        self._client = BleakClient(address, timeout=timeout)
        self._control_lock = asyncio.Lock()
        self._response_event = asyncio.Event()
        self._response_data: Optional[dict] = None
        self._pending_command: Optional[str] = None
        self._stream_callbacks: dict[str, list[Callable]] = {
            "oximetry": [],
            "df20": [],
            "df22": [],
            "df23": [],
        }

    async def connect(self):
        # Nonin requires bluez-level bonding before bleak can discover services.
        # Check and pair upfront if needed.
        await self._ensure_paired()
        await self._client.connect()
        # Control point requires encrypted link; retry after connection
        # settles and bonding completes
        for attempt in range(3):
            try:
                await self._client.start_notify(CONTROL_POINT_UUID, self._control_point_handler)
                return
            except Exception:
                if attempt == 2:
                    raise
                await asyncio.sleep(2)

    async def _ensure_paired(self):
        if sys.platform == "linux":
            await self._ensure_paired_linux()
        # On other platforms (Windows/macOS), bleak handles pairing via OS prompts

    async def _ensure_paired_linux(self):
        from dbus_fast.aio import MessageBus
        from dbus_fast import BusType, Message
        from dbus_fast.service import ServiceInterface, method
        from dbus_fast.signature import Variant

        adapter_path = "/org/bluez/hci0"
        dev_path = "/org/bluez/hci0/dev_" + self.address.replace(":", "_")

        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        try:
            # Check if already paired
            reply = await bus.call(Message(
                destination="org.bluez",
                path="/",
                interface="org.freedesktop.DBus.ObjectManager",
                member="GetManagedObjects",
            ))
            objects = reply.body[0]
            if dev_path in objects:
                dev_ifaces = objects[dev_path]
                dev_props = dev_ifaces.get("org.bluez.Device1", {})
                paired = dev_props.get("Paired")
                if paired and paired.value:
                    return

            # Register a no-input pairing agent
            agent_path = "/nonin/agent"

            class _Agent(ServiceInterface):
                @method()
                def Release(self): pass
                @method()
                def RequestConfirmation(self, device: "o", passkey: "u"): pass
                @method()
                def AuthorizeService(self, device: "o", uuid: "s"): pass
                @method()
                def Cancel(self): pass

            agent = _Agent("org.bluez.Agent1")
            bus.export(agent_path, agent)

            await bus.call(Message(
                destination="org.bluez",
                path="/org/bluez",
                interface="org.bluez.AgentManager1",
                member="RegisterAgent",
                signature="os",
                body=[agent_path, "NoInputNoOutput"],
            ))

            try:
                # Scan until device appears with Device1 interface
                await bus.call(Message(
                    destination="org.bluez",
                    path=adapter_path,
                    interface="org.bluez.Adapter1",
                    member="SetDiscoveryFilter",
                    signature="a{sv}",
                    body=[{"Transport": Variant("s", "le")}],
                ))
                await bus.call(Message(
                    destination="org.bluez",
                    path=adapter_path,
                    interface="org.bluez.Adapter1",
                    member="StartDiscovery",
                ))

                try:
                    for _ in range(15):
                        await asyncio.sleep(1)
                        reply = await bus.call(Message(
                            destination="org.bluez",
                            path="/",
                            interface="org.freedesktop.DBus.ObjectManager",
                            member="GetManagedObjects",
                        ))
                        objects = reply.body[0]
                        if dev_path in objects and "org.bluez.Device1" in objects[dev_path]:
                            break
                    else:
                        raise RuntimeError(f"Device {self.address} not found during scan")
                finally:
                    await bus.call(Message(
                        destination="org.bluez",
                        path=adapter_path,
                        interface="org.bluez.Adapter1",
                        member="StopDiscovery",
                    ))

                # Pair
                print(f"Pairing with {self.address}...")
                reply = await bus.call(Message(
                    destination="org.bluez",
                    path=dev_path,
                    interface="org.bluez.Device1",
                    member="Pair",
                ))
                if reply.message_type.value == 3:  # error
                    raise RuntimeError(f"Pairing failed: {reply.body}")

                # Disconnect so bleak can connect cleanly
                await bus.call(Message(
                    destination="org.bluez",
                    path=dev_path,
                    interface="org.bluez.Device1",
                    member="Disconnect",
                ))
                await asyncio.sleep(1)
                print("Paired successfully.")

            finally:
                await bus.call(Message(
                    destination="org.bluez",
                    path="/org/bluez",
                    interface="org.bluez.AgentManager1",
                    member="UnregisterAgent",
                    signature="o",
                    body=[agent_path],
                ))
        finally:
            bus.disconnect()

    async def disconnect(self):
        if self._client.is_connected:
            await self._client.disconnect()

    @property
    def is_connected(self) -> bool:
        return self._client.is_connected

    # Control point response handler

    def _control_point_handler(self, sender, data: bytearray):
        opcode = data[0]

        # Set Security Mode Response: [E4, result]
        if opcode == 0xE4 and len(data) == 2:
            result = data[1]
            if self._pending_command == "SET_SECURITY":
                self._response_data = {"success": result == 0x00, "result": result}
                self._response_event.set()
            return

        # Get Security Mode Response: [E5, mode]
        if opcode == 0xE5 and len(data) == 2:
            mode_byte = data[1]
            mode, name = parse_security_mode_response_byte(mode_byte)
            if self._pending_command == "GET_SECURITY":
                self._response_data = {"mode": mode, "name": name}
                self._response_event.set()
            return

        # Delete Bond Response: [E3, result]
        if opcode == 0xE3 and len(data) == 2:
            result = data[1]
            if self._pending_command == "DELETE_BOND":
                self._response_data = {"success": result == 0x00, "result": result}
                self._response_event.set()
            return

        if len(data) < 3:
            return

        result = data[1]
        length = data[2]
        payload = data[3:3 + length]

        if opcode != 0xE0:
            return

        if result == 0x02:
            self._response_data = {"error": "device_busy"}
            self._response_event.set()
            return

        if result != 0x00:
            self._response_data = {"error": f"command_failed(0x{result:02X})"}
            self._response_event.set()
            return

        if len(payload) != length:
            self._response_data = {"error": "length_mismatch"}
            self._response_event.set()
            return

        cmd = self._pending_command
        resp = {}

        if cmd == "GET_DATETIME" and length == 12:
            resp = {"datetime": parse_datetime_payload(payload)}
        elif cmd == "SET_DATETIME" and length == 1:
            resp = {"success": payload[0] == 0x06}
        elif cmd == "GET_ACTIVATION" and length == 1:
            mode, name = parse_activation_mode_payload(payload)
            resp = {"mode": mode, "name": name}
        elif cmd == "SET_ACTIVATION" and length == 1:
            resp = {"success": payload[0] == 0x06}
        elif cmd == "TURN_OFF_UPON_DISCONNECT" and length == 1:
            resp = {"success": parse_turn_off_upon_disconnect_payload(payload)}
        elif cmd == "GET_DISPLAY" and length == 1:
            mode, name = parse_display_mode_payload(payload)
            resp = {"mode": mode, "name": name}
        elif cmd == "SET_DISPLAY" and length == 1:
            resp = {"success": payload[0] == 0x06}
        elif cmd == "GET_DEVICE_ID" and length == 50:
            resp = {"device_id": parse_device_id_payload(payload)}
        elif cmd == "SET_DEVICE_ID" and length == 1:
            resp = {"success": payload[0] == 0x06}
        elif cmd == "CLEAR_MEMORY" and length == 1:
            resp = {"success": payload[0] == 0x06}
        elif cmd == "GET_STORAGE_RATE" and length == 1:
            rate, name = parse_storage_rate_payload(payload)
            resp = {"rate": rate, "name": name}
        elif cmd == "SET_STORAGE_RATE" and length == 1:
            resp = {"success": payload[0] == 0x06}
        elif cmd == "GET_CONFIG" and length == 136:
            resp = {"config": parse_config_block_payload(payload)}
        elif cmd == "SET_CONFIG" and length == 1:
            resp = {"success": payload[0] == 0x06}
        else:
            resp = {"raw": data.hex(), "payload": payload.hex()}

        self._response_data = resp
        self._response_event.set()

    async def _send_command(self, name: str, cmd_bytes: bytes, timeout: float = 5.0) -> dict:
        async with self._control_lock:
            self._response_event.clear()
            self._response_data = None
            self._pending_command = name
            await asyncio.sleep(0.2)
            await self._client.write_gatt_char(CONTROL_POINT_UUID, cmd_bytes)
            try:
                await asyncio.wait_for(self._response_event.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                raise TimeoutError(f"No response for {name} within {timeout}s")
            finally:
                self._pending_command = None
            resp = self._response_data
            if resp and "error" in resp:
                raise RuntimeError(f"{name}: {resp['error']}")
            return resp

    # Public config API

    async def get_datetime(self) -> datetime:
        resp = await self._send_command("GET_DATETIME", build_get_datetime_command())
        return resp["datetime"]

    async def set_datetime(self, dt: Optional[datetime] = None):
        if dt is None:
            dt = datetime.now()
        resp = await self._send_command("SET_DATETIME", build_set_datetime_command(dt))
        if not resp.get("success"):
            raise RuntimeError("SET_DATETIME not acknowledged")

    async def get_activation_mode(self) -> tuple:
        resp = await self._send_command("GET_ACTIVATION", build_get_activation_mode_command())
        return resp["mode"], resp["name"]

    async def set_activation_mode(self, mode: int):
        resp = await self._send_command("SET_ACTIVATION", build_set_activation_mode_command(mode))
        if not resp.get("success"):
            raise RuntimeError("SET_ACTIVATION not acknowledged")

    async def get_display_mode(self) -> tuple:
        resp = await self._send_command("GET_DISPLAY", build_get_display_mode_command())
        return resp["mode"], resp["name"]

    async def set_display_mode(self, mode: int):
        resp = await self._send_command("SET_DISPLAY", build_set_display_mode_command(mode))
        if not resp.get("success"):
            raise RuntimeError("SET_DISPLAY not acknowledged")

    async def get_storage_rate(self) -> tuple:
        resp = await self._send_command("GET_STORAGE_RATE", build_get_storage_rate_command())
        return resp["rate"], resp["name"]

    async def set_storage_rate(self, rate: int):
        resp = await self._send_command("SET_STORAGE_RATE", build_set_storage_rate_command(rate))
        if not resp.get("success"):
            raise RuntimeError("SET_STORAGE_RATE not acknowledged")

    async def get_device_id(self) -> str:
        resp = await self._send_command("GET_DEVICE_ID", build_get_device_id_command())
        return resp["device_id"]

    async def set_device_id(self, text: str):
        resp = await self._send_command("SET_DEVICE_ID", build_set_device_id_command(text))
        if not resp.get("success"):
            raise RuntimeError("SET_DEVICE_ID not acknowledged")

    async def get_security_mode(self) -> tuple:
        resp = await self._send_command("GET_SECURITY", build_get_security_mode_command())
        return resp["mode"], resp["name"]

    async def set_security_mode(self, mode: int):
        resp = await self._send_command("SET_SECURITY", build_set_security_mode_command(mode))
        if not resp.get("success"):
            raise RuntimeError("SET_SECURITY not acknowledged")

    async def get_config(self) -> dict:
        resp = await self._send_command("GET_CONFIG", build_get_config_block_command())
        return resp["config"]

    async def set_config(self, **kwargs):
        resp = await self._send_command("SET_CONFIG", build_set_configuration_command(**kwargs))
        if not resp.get("success"):
            raise RuntimeError("SET_CONFIG not acknowledged")

    async def delete_bond(self, operation: int):
        resp = await self._send_command("DELETE_BOND", build_delete_bond_command(operation))
        if not resp.get("success"):
            raise RuntimeError("DELETE_BOND not acknowledged")

    async def clear_memory(self):
        resp = await self._send_command("CLEAR_MEMORY", build_clear_memory_command())
        if not resp.get("success"):
            raise RuntimeError("CLEAR_MEMORY not acknowledged")

    async def turn_off_upon_disconnect(self):
        resp = await self._send_command("TURN_OFF_UPON_DISCONNECT", build_turn_off_upon_disconnect_command())
        if not resp.get("success"):
            raise RuntimeError("TURN_OFF_UPON_DISCONNECT not acknowledged")

    # Streaming

    def _make_notify_handler(self, stream_name: str, parser: Callable):
        def handler(sender, data: bytearray):
            try:
                parsed = parser(data)
                for cb in self._stream_callbacks[stream_name]:
                    cb(stream_name, parsed)
            except ValueError:
                pass
        return handler

    async def subscribe(self, streams: list, callback: Callable):
        if "all" in streams:
            streams = ["oximetry", "df20", "df22", "df23"]

        uuid_map = {
            "oximetry": (CONTINUOUS_OXIM_UUID, parse_continuous_oximetry),
            "df20": (PULSE_INTERVAL_DF20_UUID, parse_df20_payload),
            "df22": (PPG_DF22_UUID, parse_df22_payload),
            "df23": (DEVICE_STATUS_DF23_UUID, parse_df23_payload),
        }

        for name in streams:
            if name not in uuid_map:
                raise ValueError(f"Unknown stream: {name}")
            self._stream_callbacks[name].append(callback)
            uuid, parser = uuid_map[name]
            await self._client.start_notify(uuid, self._make_notify_handler(name, parser))
