#!/usr/bin/env python3
"""
Decode (and build) the framed app<->watch protocol seen in btsnoop_hci.log captures.

Usage:
    python suunto_decode.py capture.log              # everything
    python suunto_decode.py capture.log --music      # only /offline/music traffic
    python suunto_decode.py capture.log --grep Time  # only lines containing text

Frame format (verified against four captures, every CRC checks out):
    7E | A5 | type | len u16 LE | seq u16 LE | payload[len] | CRC32 u32 LE | 7E
    - bytes between the 7Es are byte-stuffed: 7D->7D 5D, 7E->7D 5E
    - CRC32 = zlib.crc32 over A5 .. end of payload (before stuffing)
    - the link is a BYTE STREAM: a frame may be split over several ATT writes
      or notifications (nRF Connect sends 20-byte pieces and the watch copes),
      so frames are found by the 7E markers, not by ATT packet boundaries.
Transport: ATT Write Command to handle 0x001D (phone->watch),
           ATT Notification from handle 0x0020 (watch->phone),
           CCCD for notifications is handle 0x0021 (write 01 00).
GATT: service 61353090-8231-49cc-b57a-886370740041
      write  17816557-5652-417f-909f-3aee61e5fa85 (write without response)
      notify 34802252-7185-4d5d-b431-630e7050e8f0
"""
import json, re, struct, sys, zlib

TYPES = {0x0a: "REQ", 0x02: "REQ-ACK", 0x0d: "READ", 0x05: "READ-DATA",
         0x0e: "WRITE", 0x07: "WRITE-ACK", 0x10: "READ2", 0x08: "READ2-DATA",
         0x11: "WRITE2", 0x09: "WRITE2-ACK", 0x12: "HELLO", 0x13: "HELLO-RSP",
         0x01: "TYPE01"}
STATUS = {0x64: "100 Continue", 0xc8: "200 OK", 0xcc: "204 No Content",
          0x194: "404 Not Found", 0x1f4: "500 Server Error"}
HAS_STATUS = {0x02, 0x05, 0x07, 0x08, 0x09}
BTSNOOP_EPOCH_US = 0x00dcddb30f2f8000  # btsnoop clock (us since year 0) at the Unix epoch


# ---------------------------------------------------------------- framing
def stuff(b: bytes) -> bytes:
    return b.replace(b"\x7d", b"\x7d\x5d").replace(b"\x7e", b"\x7d\x5e")


def unstuff(b: bytes) -> bytes:
    out, i = bytearray(), 0
    while i < len(b):
        if b[i] == 0x7d and i + 1 < len(b):
            out.append(b[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(b[i])
            i += 1
    return bytes(out)


def encode(typ: int, seq: int, payload: bytes) -> bytes:
    body = bytes([0xA5, typ]) + struct.pack("<HH", len(payload), seq) + payload
    return b"\x7e" + stuff(body + struct.pack("<I", zlib.crc32(body))) + b"\x7e"


def decode(value: bytes):
    """Return dict for one complete frame (including both 7Es), or None."""
    if len(value) < 12 or value[0] != 0x7e or value[-1] != 0x7e:
        return None
    f = unstuff(value[1:-1])
    if len(f) < 10:
        return None
    body, crc = f[:-4], f[-4:]
    return dict(type=f[1], seq=struct.unpack("<H", f[4:6])[0], payload=f[6:-4],
                crc_ok=struct.pack("<I", zlib.crc32(body)) == crc)


# ------------------------------------------------- request/body builders
def request(seq: int, path: str) -> bytes:
    """Phone->watch 'open this resource' frame (type 0x0a)."""
    return encode(0x0a, seq, b"\x01\x80\x00" + bytes([len(path)]) + path.encode())


def json_body(obj) -> bytes:
    """JSON wrapper as observed: 0d 00 02 L 00 00 L 00 00 L 00 + JSON
    (L = JSON length; only seen for JSON < 256 bytes, so 1- vs 2-byte L is unconfirmed)."""
    j = json.dumps(obj, separators=(",", ":")).encode()
    L = struct.pack("<H", len(j))
    return b"\x0d\x00\x02" + L + b"\x00" + L + b"\x00" + L + j


def write_frame(seq: int, resource_id: bytes, body: bytes) -> bytes:
    """Type 0x0e write. resource_id is the 3 bytes (f0 xx yy) from the watch's REQ-ACK."""
    return encode(0x0e, seq, resource_id + b"\x01\x80\x00" + b"\x01" + body)


def playlist_obj(name: str, playlist_id: int, sort_id: int, keys):
    return {"playList": {"sortId": sort_id, "playListId": playlist_id,
                         "musicNum": len(keys), "playListName": name,
                         "musicItems": [{"key": k} for k in keys]}}


# ------------------------------------------------------------ btsnoop
def read_btsnoop(path):
    d = open(path, "rb").read()
    assert d[:8] == b"btsnoop\0", "not a btsnoop file"
    off, n = 16, 0
    while off + 24 <= len(d):
        orig, incl, flags, drops, ts = struct.unpack(">IIIIq", d[off:off + 24])
        off += 24
        n += 1
        yield n, flags & 1, ts, d[off:off + incl]
        off += incl


def att_values(path):
    """Yield (packet#, rx, ts, att_opcode, value) after L2CAP reassembly.
    Continuation fragments whose first fragment is missing yield opcode None."""
    buf = {}
    for n, rx, ts, p in read_btsnoop(path):
        if p[0] != 2:  # only ACL data
            continue
        h, alen = struct.unpack("<HH", p[1:5])
        pb = (h >> 12) & 3
        data = p[5:5 + alen]
        if pb in (0, 2):
            ll, cid = struct.unpack("<HH", data[:4])
            buf[rx] = [n, ts, ll, cid, data[4:]]
        else:
            if rx not in buf:
                yield n, rx, ts, None, data
                continue
            buf[rx][4] += data
        b = buf[rx]
        if len(b[4]) >= b[2]:
            del buf[rx]
            if b[3] == 4 and b[4]:
                att = b[4][:b[2]]
                yield b[0], rx, b[1], att[0], att[1:]


def stream_frames(path):
    """Reassemble the two byte streams and yield (packet#, ts, rx, frame_dict_or_None, nbytes),
    ordered by the time the frame's last byte arrived."""
    streams = {0: bytearray(), 1: bytearray()}
    marks = {0: [], 1: []}  # (cumulative length, packet#, ts)
    for n, rx, ts, op, val in att_values(path):
        if op in (0x52, 0x1b):
            streams[rx] += val[2:]  # skip 2-byte ATT handle
            marks[rx].append((len(streams[rx]), n, ts))
    out = []
    for rx in (0, 1):
        off = 0
        for piece in bytes(streams[rx]).split(b"\x7e"):
            off += len(piece) + 1
            if not piece:
                continue
            n, ts = next(((n, t) for L, n, t in marks[rx] if L >= off), (None, None))
            out.append((n, ts, rx, decode(b"\x7e" + piece + b"\x7e"), len(piece)))
    out.sort(key=lambda x: ((x[1] or 0), (x[0] or 0)))
    return out


# --------------------------------------------------------------- main
def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    music = "--music" in args
    grep = args[args.index("--grep") + 1] if "--grep" in args else None
    pending, ids = {}, {}  # (rx,seq)->path ; resource id -> path
    t0 = None
    frames = list(stream_frames(args[0]))
    # First pass: learn which resource id belongs to which path, so frames the phone
    # pipelined *before* the watch's ack arrived (e.g. the empty write) are still labelled.
    for _n, _ts, _rx, _fr, _nb in frames:
        if _fr and _fr["crc_ok"]:
            if _fr["type"] == 0x0a:
                pending[(_rx, _fr["seq"])] = _fr["payload"][4:4 + _fr["payload"][3]].decode(errors="replace")
            elif _fr["type"] == 0x02 and (not _rx, _fr["seq"]) in pending:
                ids[_fr["payload"][:3]] = pending[(not _rx, _fr["seq"])]
    for n, ts, rx, fr, nbytes in frames:
        t0 = t0 or ts
        who = "watch->phone" if rx else "phone->watch"
        stamp = f"+{(ts - t0) / 1e6:7.2f}s"
        if not fr or not fr["crc_ok"]:
            if not music:
                _emit(f"{n:4} {stamp} {who} [partial/corrupt frame, {nbytes} bytes - capture may be missing its start]", grep)
            continue
        t, seq, pay = fr["type"], fr["seq"], fr["payload"]
        label = TYPES.get(t, f"type{t:02x}")
        path, extra = None, ""
        if t == 0x0a:
            path = pay[4:4 + pay[3]].decode(errors="replace")
            pending[(rx, seq)] = path
            extra = path
        elif t == 0x02 and (not rx, seq) in pending:
            ids[pay[:3]] = pending[(not rx, seq)]
            path = ids[pay[:3]]
        else:
            path = ids.get(pay[:3])
        if t in HAS_STATUS and len(pay) >= 8:
            st = struct.unpack("<H", pay[6:8])[0]
            extra = STATUS.get(st, f"status {st:#x}")
            body = pay[8:]
        else:
            body = pay[7:] if t in (0x0d, 0x0e, 0x10, 0x11) else pay
        m = re.search(rb"\{.*\}", body)
        if m:
            extra += " " + m.group(0).decode(errors="replace")
        elif body and t != 0x0a:
            extra += " " + body.hex()
        if music and not ((path or "").startswith("/offline/music")):
            continue
        idtxt = pay[:3].hex() if t != 0x0a else "-"
        _emit(f"{n:4} {stamp} {who} {label:10} seq={seq:#06x} id={idtxt:6} {(path or ''):28} {extra}", grep)


def _emit(line, grep):
    if grep is None or grep.lower() in line.lower():
        try:
            print(line)
        except BrokenPipeError:
            sys.exit(0)


if __name__ == "__main__":
    main()
