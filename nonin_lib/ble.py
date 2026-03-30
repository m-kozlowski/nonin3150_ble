import asyncio
import sys
from datetime import datetime
from typing import Callable, Optional

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from nonin_lib.common import (
    NONIN_SERVICE_UUID, CONTINUOUS_OXIM_UUID, CONTROL_POINT_UUID,
    DEVICE_STATUS_DF23_UUID, PULSE_INTERVAL_DF20_UUID, PPG_DF22_UUID,
    MEMORY_PLAYBACK_UUID,
    parse_continuous_oximetry, parse_df20_payload, parse_df22_payload,
    parse_df23_payload, parse_datetime_payload, parse_activation_mode_payload,
    parse_turn_off_upon_disconnect_payload, parse_security_mode_response_byte,
    parse_display_mode_payload, parse_device_id_payload,
    parse_storage_rate_payload, parse_config_block_payload,
    parse_memory_data,
    build_get_datetime_command, build_set_datetime_command,
    build_get_activation_mode_command, build_set_activation_mode_command,
    build_turn_off_upon_disconnect_command,
    build_get_security_mode_command, build_set_security_mode_command,
    build_set_display_mode_command, build_get_display_mode_command,
    build_set_device_id_command, build_get_device_id_command,
    build_get_config_block_command, build_set_configuration_command,
    build_delete_bond_command, build_clear_memory_command,
    build_set_storage_rate_command, build_get_storage_rate_command,
    build_memory_playback_command, build_cancel_memory_playback_command,
)


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


# High-level BLE client

class NoninBLE:
    def __init__(self, address: str, timeout: float = 30.0):
        self.address = address
        self._timeout = timeout
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
        await self._ensure_paired()
        for conn_attempt in range(3):
            device = await BleakScanner.find_device_by_address(
                self.address, timeout=self._timeout)
            if device is None:
                raise RuntimeError(f"Device {self.address} not found")
            try:
                await self._client.connect()
                break
            except Exception:
                if conn_attempt == 2:
                    raise
                await asyncio.sleep(5)
                self._client = BleakClient(self.address, timeout=self._timeout)
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

    async def _ensure_paired_linux(self):
        from dbus_fast.aio import MessageBus
        from dbus_fast import BusType, Message
        from dbus_fast.service import ServiceInterface, method
        from dbus_fast.signature import Variant

        adapter_path = "/org/bluez/hci0"
        dev_path = "/org/bluez/hci0/dev_" + self.address.replace(":", "_")

        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        try:
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

                print(f"Pairing with {self.address}...")
                reply = await bus.call(Message(
                    destination="org.bluez",
                    path=dev_path,
                    interface="org.bluez.Device1",
                    member="Pair",
                ))
                if reply.message_type.value == 3:
                    raise RuntimeError(f"Pairing failed: {reply.body}")

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

        if opcode == 0xE4 and len(data) == 2:
            result = data[1]
            if self._pending_command == "SET_SECURITY":
                self._response_data = {"success": result == 0x00, "result": result}
                self._response_event.set()
            return

        if opcode == 0xE5 and len(data) == 2:
            mode_byte = data[1]
            mode, name = parse_security_mode_response_byte(mode_byte)
            if self._pending_command == "GET_SECURITY":
                self._response_data = {"mode": mode, "name": name}
                self._response_event.set()
            return

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

    # Memory playback

    async def download_memory(
        self,
        after: Optional[datetime] = None,
        before: Optional[datetime] = None,
        max_sessions: Optional[int] = None,
        skip_sessions: int = 0,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> list:
        raw_chunks = []
        last_receive_time = [asyncio.get_event_loop().time()]
        cancel_requested = [False]

        def on_indication(sender, data: bytearray):
            raw_chunks.append(bytes(data))
            last_receive_time[0] = asyncio.get_event_loop().time()
            if progress_callback:
                total = sum(len(c) for c in raw_chunks)
                progress_callback(total)

        await self._client.start_notify(MEMORY_PLAYBACK_UUID, on_indication)

        await self._client.write_gatt_char(
            CONTROL_POINT_UUID, build_memory_playback_command())

        while True:
            await asyncio.sleep(1)
            elapsed = asyncio.get_event_loop().time() - last_receive_time[0]
            if raw_chunks and elapsed > 3:
                break
            if not raw_chunks and elapsed > 10:
                break

            if not cancel_requested[0]:
                raw = b"".join(raw_chunks)
                sessions = parse_memory_data(raw)
                should_cancel = False

                if max_sessions is not None:
                    total_needed = skip_sessions + max_sessions
                    if len(sessions) >= total_needed:
                        should_cancel = True

                if after:
                    for s in sessions:
                        if s["start_time"] and s["start_time"] < after:
                            should_cancel = True
                            break

                if should_cancel:
                    try:
                        await self._client.write_gatt_char(
                            CONTROL_POINT_UUID,
                            build_cancel_memory_playback_command())
                    except Exception:
                        pass
                    cancel_requested[0] = True
                    await asyncio.sleep(2)
                    break

        try:
            await self._client.stop_notify(MEMORY_PLAYBACK_UUID)
        except Exception:
            pass

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

    async def cancel_memory_playback(self):
        await self._client.write_gatt_char(
            CONTROL_POINT_UUID, build_cancel_memory_playback_command())

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
