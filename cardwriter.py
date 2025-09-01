import sys, serial, time

PORT = "COM5" if sys.platform.startswith("win") else "/dev/ttyACM0"
BAUD = 115200
TIMEOUT = 2.0

WRITE_IF_EMPTY_URL = "https://example.com/hello"

URI_PREFIX = [
    "", "http://www.", "https://www.", "http://", "https://",
    "tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.",
    "ftps://", "sftp://", "smb://", "nfs://", "ftp://",
    "dav://", "news:", "telnet://", "imap:", "rtsp://",
    "urn:", "pop:", "sip:", "sips:", "tftp:",
    "btspp://", "btl2cap://", "btgoep://", "tcpobex://", "irdaobex://",
    "file://", "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:",
    "urn:epc:raw:", "urn:epc:", "urn:nfc:"
]


def read_tag_dump(ser):
    """Return dict with uid(str), data(bytes) after seeing TAG_BEGIN..TAG_END, else None."""
    uid = None
    length = None
    hexdata = None

    # wait for TAG_BEGIN
    while True:
        line = ser.readline().decode("ascii", "ignore").strip()
        if not line:
            return None
        if line == "TAG_BEGIN":
            break

    # read lines until TAG_END
    while True:
        line = ser.readline().decode("ascii", "ignore").strip()
        if not line:
            return None
        if line.startswith("UID:"):
            uid = line[4:].strip()
        elif line.startswith("LEN:"):
            try: length = int(line[4:].strip())
            except: length = None
        elif line.startswith("HEX:"):
            hexdata = line[4:].strip()
        elif line == "TAG_END":
            break

    if hexdata is None or uid is None or length is None:
        return None
    data = bytes.fromhex(hexdata)
    if len(data) != length:
        print(f"[warn] Length mismatch: header {length}, got {len(data)} bytes")
    return {"uid": uid, "data": data}


def tlv_iter(buf):
    i, n = 0, len(buf)
    while i < n:
        t = buf[i]; i += 1
        if t == 0xFE:  # Terminator
            yield (t, 0, b"")
            return
        if t == 0x00:  # Null
            yield (t, 0, b"")
            continue
        if i >= n: return
        L = buf[i]; i += 1
        if L != 0xFF:
            length = L
        else:
            if i + 1 >= n: return
            length = (buf[i] << 8) | buf[i+1]
            i += 2
        if i + length > n: return
        val = buf[i:i+length]; i += length
        yield (t, length, val)


def parse_ndef_records(msg):
    """Yield dicts for NDEF records from message bytes."""
    i, n = 0, len(msg)
    while i < n:
        if i + 2 > n: break
        hdr = msg[i]; i += 1
        mb = bool(hdr & 0x80); me = bool(hdr & 0x40)
        cf = bool(hdr & 0x20); sr = bool(hdr & 0x10)
        il = bool(hdr & 0x08); tnf = hdr & 0x07

        tlen = msg[i]; i += 1
        if sr:
            if i + 1 > n: break
            plen = msg[i]; i += 1
        else:
            if i + 4 > n: break
            plen = (msg[i] << 24) | (msg[i+1] << 16) | (msg[i+2] << 8) | msg[i+3]
            i += 4

        ilen = msg[i]; i += 1 if il else 0
        if i + tlen > n: break
        rtype = msg[i:i+tlen]; i += tlen
        rid = b""
        if il:
            if i + ilen > n: break
            rid = msg[i:i+ilen]; i += ilen
        if i + plen > n: break
        payload = msg[i:i+plen]; i += plen

        yield {
            "mb": mb, "me": me, "cf": cf, "sr": sr, "il": il, "tnf": tnf,
            "type": rtype, "id": rid, "payload": payload
        }
        if me: break


def decode_well_known(record):
    t = record["type"]
    if t == b"U":  # URI
        if not record["payload"]:
            return ("URI", "")
        code = record["payload"][0]
        prefix = URI_PREFIX[code] if code < len(URI_PREFIX) else ""
        suffix = record["payload"][1:].decode("utf-8", "ignore")
        return ("URI", prefix + suffix)
    if t == b"T":  # Text
        p = record["payload"]
        if not p: return ("Text", "")
        status = p[0]; lang_len = status & 0x3F; utf16 = bool(status & 0x80)
        lang = p[1:1+lang_len].decode("ascii", "ignore")
        text = p[1+lang_len:]
        if utf16:
            # Often big-endian without BOM; try both
            try:
                s = text.decode("utf-16")
            except:
                try: s = text.decode("utf-16-be")
                except: s = text.decode("utf-8", "ignore")
        else:
            s = text.decode("utf-8", "ignore")
        return ("Text", f"[{lang}] {s}")
    return (None, None)


def print_records(records):
    count = 0
    for idx, rec in enumerate(records):
        tnf = rec["tnf"]
        rtype = rec["type"]
        print(f"Record {idx}: TNF=0x{tnf:02X}, Type={rtype!r}, PayloadLen={len(rec['payload'])}")
        kind, val = decode_well_known(rec)
        if kind:
            print(f"  {kind}: {val}")
        count += 1
    return count


def find_ndef_message(user_mem):
    # NTAG21x user memory starts at page 4; TLVs are stored there.
    for t, length, val in tlv_iter(user_mem):
        if t == 0x03:  # NDEF Message TLV
            return val
        if t == 0xFE:  # Terminator
            break
    return None


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else PORT
    write_url = sys.argv[2] if len(sys.argv) > 2 else WRITE_IF_EMPTY_URL

    with serial.Serial(port, BAUD, timeout=TIMEOUT) as ser:
        print(f"[i] Listening on {port} @ {BAUD}…")
        while True:
            tag = read_tag_dump(ser)
            if not tag:
                continue
            uid = tag["uid"]
            data = tag["data"]
            print(f"\n== TAG UID {uid} ==")
            msg = find_ndef_message(data)
            recs = list(parse_ndef_records(msg))
            count = print_records(recs)
            if count == 0:
                if write_url:
                    print(f"[i] Writing URI because empty: {write_url}")
                    ser.write(f"WRITEURI {write_url}\n".encode("utf-8"))
                    ack = ser.readline().decode("ascii", "ignore").strip()
                    if ack:
                        print(f"[board] {ack}")
                    confirm = read_tag_dump(ser)
                    if confirm:
                        print("[i] Re-read after write:")
                        msg2 = find_ndef_message(confirm["data"])
                        if msg2:
                            recs = list(parse_ndef_records(msg2))
                            _ = print_records(recs)
                        else:
                            print("[!] Still no NDEF after write.")
                continue


if __name__ == "__main__":
    main()
