#!/usr/bin/env python3
"""
suunto_client.py - EXPERIMENTAL BLE client for the offline-music playlists on a Suunto Run.

Built from reverse-engineered captures (see suunto_decode.py for the frame format).
It has NOT been tested against real hardware by its author - only against a simulated
watch - so treat every command as an experiment. Keep suunto_decode.py next to this file.

Setup:
    pip install bleak
Before running: turn Bluetooth OFF on your phone (or disconnect the watch there) so the
watch advertises to the computer, and make sure the Suunto app is not holding the connection.

Commands:
    python suunto_client.py scan
    python suunto_client.py services                   # connect and print the watch's GATT table (diagnostic)
    python suunto_client.py probe                      # hello + read version + playlists (read-only)
    python suunto_client.py songs                      # list the song keys on the watch (read-only)
    python suunto_client.py add NAME KEY [KEY ...]     # create a playlist from song keys
    python suunto_client.py delete PLAYLIST_ID         # delete a playlist you created

Options (put before or after the command):
    --address ADDR    connect to this address (macOS: the UUID that `scan` prints)
    --appinfo         mimic the app: read launcherStatus + write AppInfo before the add
    --gap SECONDS     pause between the steps of one transaction (the app uses ~0)
    --chunk N         bytes per BLE write (default 20, the size nRF Connect used)
    --pair            ask the OS to pair/bond with the watch right after connecting
    --uncached        (Windows) ignore Windows' cached GATT table and rediscover it
    --adapter NAME    (Linux) Bluetooth adapter, default hci0 (see `bluetoothctl list` / `hciconfig`)
    -v                print every frame sent and received
"""
import argparse
import asyncio
import json
import struct
import sys
import time

from suunto_decode import TYPES, STATUS, decode, encode, json_body, playlist_obj, request, write_frame

SERVICE_UUID = "61353090-8231-49cc-b57a-886370740041"
WRITE_UUID = "17816557-5652-417f-909f-3aee61e5fa85"   # write without response (ATT handle 0x1D)
NOTIFY_UUID = "34802252-7185-4d5d-b431-630e7050e8f0"  # notifications (ATT handle 0x20)

# The phone's "hello", replayed verbatim from the captures (the watch answered it both times).
HELLO_PAYLOAD = bytes.fromhex("0909201645564110044110100000000401020000000000030000000000000000")


class ProtocolError(Exception):
    pass


def status_of(fr):
    return struct.unpack("<H", fr["payload"][6:8])[0]


def describe(fr):
    t = TYPES.get(fr["type"], f"type{fr['type']:02x}")
    extra = ""
    if fr["type"] in (0x02, 0x05, 0x07) and len(fr["payload"]) >= 8:
        extra = STATUS.get(status_of(fr), f"status {status_of(fr):#x}")
    return f"{t} seq={fr['seq']:#06x} {extra}"


class Link:
    """Frames over a byte stream: chunks outgoing frames, reassembles incoming ones."""

    def __init__(self, write, chunk=20, verbose=False, chunk_delay=0.0):
        self._write = write
        self.chunk = chunk
        self.verbose = verbose
        self.chunk_delay = chunk_delay
        self._buf = bytearray()
        self._q = asyncio.Queue()
        self._seq = 0x0200

    def next_seq(self):
        s = self._seq
        self._seq = (self._seq + 1) & 0xFFFF
        return s

    async def send(self, frame):
        if self.verbose:
            fr = decode(frame)
            print(f"  >> {describe(fr)} {frame.hex()[:60]}")
        for i in range(0, len(frame), self.chunk):
            await self._write(frame[i:i + self.chunk])
            if self.chunk_delay:
                await asyncio.sleep(self.chunk_delay)

    def on_notify(self, data):
        self._buf += data
        while True:
            start = self._buf.find(b"\x7e")
            if start < 0:
                self._buf.clear()
                return
            end = self._buf.find(b"\x7e", start + 1)
            if end < 0:
                del self._buf[:start]
                return
            if end == start + 1:  # "7E 7E": the second one starts the real frame
                del self._buf[:end]
                continue
            piece = bytes(self._buf[start:end + 1])
            del self._buf[:end + 1]
            fr = decode(piece)
            if fr and fr["crc_ok"]:
                self._q.put_nowait(fr)

    async def expect(self, types, seq, timeout=6.0):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProtocolError(f"timed out waiting for reply to seq {seq:#06x}")
            try:
                fr = await asyncio.wait_for(self._q.get(), remaining)
            except asyncio.TimeoutError:
                raise ProtocolError(f"timed out waiting for reply to seq {seq:#06x}")
            if self.verbose:
                print(f"  << {describe(fr)}")
            if fr["type"] in types and fr["seq"] == seq:
                return fr
            # anything else (e.g. the watch's own requests) is ignored


def parse_body(b):
    """JSON (wrapped), a small integer (07 00 <u32>), or raw bytes."""
    if b"{" in b:
        return json.loads(b[b.index(b"{"):].decode())
    if b[:2] == b"\x07\x00" and len(b) >= 6:
        return struct.unpack("<I", b[2:6])[0]
    return b


async def pause(gap):
    if gap:
        await asyncio.sleep(gap)


async def hello(link):
    await link.send(encode(0x12, 0, HELLO_PAYLOAD))
    await link.expect({0x13}, 0)


async def open_resource(link, path):
    seq = link.next_seq()
    await link.send(request(seq, path))
    ack = await link.expect({0x02}, seq)
    st = status_of(ack)
    if st != 200:
        raise ProtocolError(f"{path}: {STATUS.get(st, hex(st))}")
    return ack["payload"][:3]  # resource id, e.g. f0 af 06


async def read(link, path, gap=0.0):
    rid = await open_resource(link, path)
    await pause(gap)
    seq = link.next_seq()
    await link.send(encode(0x0d, seq, rid + b"\x01\x80\x00\x00"))
    fr = await link.expect({0x05}, seq)
    st = status_of(fr)
    if st != 200:
        raise ProtocolError(f"{path} read: {STATUS.get(st, hex(st))}")
    return parse_body(fr["payload"][8:])


async def write_json(link, path, obj, gap=0.0):
    rid = await open_resource(link, path)
    await pause(gap)
    seq = link.next_seq()
    await link.send(encode(0x0e, seq, rid + b"\x01\x80\x00\x00"))  # empty write -> 100 Continue
    fr = await link.expect({0x07}, seq)
    if status_of(fr) != 100:
        raise ProtocolError(f"{path}: expected 100 Continue, got {STATUS.get(status_of(fr), hex(status_of(fr)))}")
    await pause(gap)
    seq = link.next_seq()
    await link.send(write_frame(seq, rid, json_body(obj)))
    fr = await link.expect({0x07}, seq)
    st = status_of(fr)
    if st != 200:
        raise ProtocolError(f"{path}: body rejected with {STATUS.get(st, hex(st))}")


async def announce_app(link):
    """What the Suunto app does when it opens the music screen (capture 2)."""
    await read(link, "/settings/user/launcherStatus")
    rid = await open_resource(link, "/Settings/Device/AppInfo")
    seq = link.next_seq()
    await link.send(encode(0x0e, seq, rid + b"\x01\x80\x00\x01" + bytes.fromhex("023402100000")))
    fr = await link.expect({0x07}, seq)
    if status_of(fr) != 200:
        raise ProtocolError("AppInfo write rejected")


async def add_playlist(link, name, keys, gap=0.0, appinfo=False):
    if appinfo:
        await announce_app(link)
    await read(link, "/offline/music/version")
    existing = (await read(link, "/offline/music/playLists"))["playLists"]
    songs = (await read(link, "/offline/music/allSongs"))["playList"]["musicItems"]
    have = {s["key"] for s in songs}
    missing = [k for k in keys if k not in have]
    if missing:
        raise ProtocolError(f"keys not on the watch: {missing}")
    sort_id = max(p["sortId"] for p in existing) + 1
    # The app's playListId is its LOCAL wall-clock time expressed as Unix seconds.
    pid = int(time.time()) + time.localtime().tm_gmtoff
    await write_json(link, "/offline/music/List/add", playlist_obj(name, pid, sort_id, keys), gap=gap)
    after = (await read(link, "/offline/music/playLists"))["playLists"]
    print("playlists now:", [(p["playListName"], p["playListId"], p["musicNum"]) for p in after])
    return pid


async def delete_playlist(link, pid):
    if pid == 65535:
        raise ProtocolError("refusing to delete the built-in 'All songs' list")
    rid = await open_resource(link, "/offline/music/List/delete")
    seq = link.next_seq()
    await link.send(encode(0x0e, seq, rid + b"\x01\x80\x00\x01\x07\x00" + struct.pack("<I", pid)))
    fr = await link.expect({0x07}, seq)
    if status_of(fr) != 200:
        raise ProtocolError(f"delete rejected: {STATUS.get(status_of(fr), hex(status_of(fr)))}")
    print("deleted", pid)


def dump_services(client):
    print("GATT table as seen by this computer:")
    for svc in client.services:
        print(f"  service {svc.uuid}")
        for ch in svc.characteristics:
            print(f"    [{ch.handle:#06x}] char {ch.uuid}  {','.join(ch.properties)}")
            for d in ch.descriptors:
                print(f"        [{d.handle:#06x}] descriptor {d.uuid}")


async def run_command(link, args):
    await hello(link)
    print("hello ok")
    if args.cmd == "probe":
        print("version:", await read(link, "/offline/music/version"))
        print("playlists:", json.dumps(await read(link, "/offline/music/playLists")))
    elif args.cmd == "songs":
        print(json.dumps(await read(link, "/offline/music/allSongs")))
    elif args.cmd == "add":
        pid = await add_playlist(link, args.name, [int(k) for k in args.keys], gap=args.gap, appinfo=args.appinfo)
        print("created playlist id", pid, "(delete with: delete", pid, ")")
    elif args.cmd == "delete":
        await delete_playlist(link, int(args.playlist_id))


async def main_async(args):
    from bleak import BleakClient, BleakScanner  # imported late so the module loads without bleak

    if args.cmd == "scan":
        for d in await BleakScanner.discover(timeout=10.0):
            print(d.address, d.name)
        return
    dev = args.address
    if dev and sys.platform.startswith("linux") and not args.force_scan:
        dev = bluez_device(dev, args.adapter)   # skip the scan; BlueZ already knows the watch
    if not dev:
        print("scanning for a device named SUUNTO* ...")
        dev = await BleakScanner.find_device_by_filter(
            lambda d, ad: (d.name or "").upper().startswith("SUUNTO"), timeout=20.0)
        if not dev and sys.platform.startswith("linux"):
            dev = paired_suunto_linux()
            if dev:
                print("not advertising, but found a paired watch in BlueZ:", dev)
                dev = bluez_device(dev, args.adapter)
        if not dev:
            sys.exit("watch not found - is phone Bluetooth off? try `scan` or --address")
    kwargs = {}
    if args.uncached and sys.platform == "win32":
        kwargs["winrt"] = dict(use_cached_services=False)
    client = BleakClient(dev, **kwargs)
    try:
        await client.connect()
    except Exception as e:
        if sys.platform.startswith("linux"):
            addr = args.address or getattr(dev, "address", "")
            print(f"connect failed: {e!r}\n\nWhat BlueZ knows about {addr}:\n{bluetoothctl_info(addr)}")
        raise
    try:
        if args.pair:
            try:
                print("pairing:", await client.pair())
            except Exception as e:  # pairing support varies by OS/adapter
                print("pair failed:", e)
        have = {c.uuid.lower() for s in client.services for c in s.characteristics}
        if args.cmd == "services" or WRITE_UUID not in have or NOTIFY_UUID not in have:
            dump_services(client)
            if args.cmd != "services":
                sys.exit("\nerror: the Suunto characteristics are not visible to this computer "
                         "(see the table above). Try --uncached (Windows) or --pair, and send me this output.")
            return
        link = Link(lambda data: client.write_gatt_char(WRITE_UUID, data, response=False),
                    chunk=args.chunk, verbose=args.verbose)
        await client.start_notify(NOTIFY_UUID, lambda _h, data: link.on_notify(bytes(data)))
        await run_command(link, args)
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


def bluez_device(addr, adapter="hci0"):
    """Linux/BlueZ: bleak normally scans for the address before connecting, but a watch that is
    already connected or paired is not advertising. Point bleak straight at BlueZ's own record."""
    from bleak.backends.device import BLEDevice
    path = f"/org/bluez/{adapter}/dev_{addr.upper().replace(':', '_')}"
    details = {"path": path, "props": {}}
    try:
        return BLEDevice(addr, "SUUNTO", details, rssi=0)  # older bleak
    except TypeError:
        return BLEDevice(addr, "SUUNTO", details)          # newer bleak


def bluetoothctl_info(addr):
    import subprocess
    try:
        return subprocess.run(["bluetoothctl", "info", addr], capture_output=True, text=True, timeout=10).stdout
    except Exception as e:
        return f"(could not run bluetoothctl: {e})"


def paired_suunto_linux():
    """On Linux/BlueZ a bonded watch may be connected to this computer (so it is not advertising).
    Look it up among the paired devices instead of scanning for it."""
    import subprocess
    for cmd in (["bluetoothctl", "devices", "Paired"], ["bluetoothctl", "paired-devices"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
        except Exception:
            continue
        for line in out.splitlines():
            parts = line.split(maxsplit=2)  # "Device AA:BB:CC:DD:EE:FF Name"
            if len(parts) == 3 and parts[0] == "Device" and parts[2].upper().startswith("SUUNTO"):
                return parts[1]
    return None


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--address")
    p.add_argument("--appinfo", action="store_true")
    p.add_argument("--gap", type=float, default=0.0)
    p.add_argument("--chunk", type=int, default=20)
    p.add_argument("--pair", action="store_true")
    p.add_argument("--adapter", default="hci0", help="Linux: Bluetooth adapter name (default hci0)")
    p.add_argument("--force-scan", action="store_true", help="Linux: scan for --address instead of using BlueZ's record")
    p.add_argument("--uncached", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan")
    sub.add_parser("services")
    sub.add_parser("probe")
    sub.add_parser("songs")
    a = sub.add_parser("add")
    a.add_argument("name")
    a.add_argument("keys", nargs="+")
    d = sub.add_parser("delete")
    d.add_argument("playlist_id")
    return p.parse_args(argv)


if __name__ == "__main__":
    try:
        asyncio.run(main_async(parse_args()))
    except ProtocolError as e:
        sys.exit(f"error: {e}")
