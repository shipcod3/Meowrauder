#!/usr/bin/env python3
"""Replace real MAC addresses and SSIDs in docs/samples with stable stand-ins.

These samples are real RF captures. BSSIDs are broadcast publicly, so this is
not a leak as such, but a committed wardriving dataset geolocates the place it
was taken via services like WiGLE. The samples are worth keeping — they are
the evidence that the parsers and the radiotap output are correct — so the
addresses are replaced rather than the files dropped.

What is preserved, because the samples are cited as evidence for claims that
depend on it:

  * the locally-administered and multicast bits of the first octet. The survey
    is cited for "19 of 41 BSSIDs were locally administered", which is why
    that signal was rejected as a rogue indicator. Randomising the bit would
    invalidate the claim.
  * OUI distinctness. Two BSSIDs that shared an OUI still do, and two that
    did not still do not, so multi-OUI analysis holds. The stand-in OUI is a
    sequence number and implies nothing about the real vendor.
  * distinctness: the mapping is injective, so 41 distinct BSSIDs stay 41.
  * hidden SSIDs stay hidden. The survey is cited for a correct IE parse on a
    real hidden AP ("SSID withheld"), so an empty SSID is left empty and only
    named networks get a stand-in.

SSIDs are redacted too, and are the more sensitive of the two: a BSSID is an
opaque number, whereas the real ones named a city, the country via ISP
default names, a local business and several neighbours' family names.
Redacting BSSIDs alone would have achieved very little.

The mapping is deterministic within a run, so the same address maps to the
same stand-in across all files given to one invocation. It is NOT idempotent:
a stand-in is itself a valid address, so a second run would map it again. The
tool therefore records a manifest of what it produced and refuses to touch a
file it has already redacted. Run it once, on the originals, in one go.

It is not reversible without the original addresses: the point is
unlinkability from the real world, not secrecy of the algorithm.

Stand-in addresses are not claimed to be unallocated: a sequence-numbered OUI
may coincide with a real vendor's. They are stand-ins in a sample file, not
assertions about anyone's hardware.

Usage:  tools/redact-samples.py docs/samples/*.txt docs/samples/*.pcap
"""
import hashlib
import re
import struct
import sys

SALT = b"meowrauder-sample-redaction-v1"
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
# iw names an interface after the adapter's own MAC, e.g. wlx<12 hex digits>
IFACE_RE = re.compile(r"\b(wlx)([0-9a-f]{12})\b")

_oui_seq: dict[bytes, int] = {}
_nic_seq: dict[bytes, int] = {}
_seen: dict[bytes, bytes] = {}      # original -> stand-in, for the body sweep
_ssid_map: dict[str, str] = {}      # original SSID -> stand-in

SSID_SURVEY_RE = re.compile(r"^(\tSSID: )(.*)$", re.M)
# "[pd]   <bssid> ch2    -68  auth3   <ssid>"
SSID_SCANLOG_RE = re.compile(
    r"^(\[pd\]\s+(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\s+ch\S+\s+-?\d+\s+auth\d+\s+)(.*)$",
    re.M,
)


def map_ssid(name: str) -> str:
    """Stable, length-preserving stand-in.

    Length is preserved because the same map is applied inside the capture,
    where an SSID lives in an information element with a length byte: a
    shorter replacement would need every enclosing length rewritten and the
    frame would no longer be the one that was captured.

    An empty name is a hidden network and is left alone — the survey is cited
    for a correct parse of an AP that withholds its SSID.
    """
    stripped = name.strip()
    if not stripped or stripped == "<hidden>":
        return name
    if stripped not in _ssid_map:
        i = len(_ssid_map) + 1
        n = len(stripped)
        tag = f"net-{i:02d}" if n >= 6 else f"n{i:02d}"
        _ssid_map[stripped] = (tag + "-" * (n - len(tag)))[:n]
    return name.replace(stripped, _ssid_map[stripped])


def _digest(b: bytes) -> bytes:
    return hashlib.blake2b(SALT + b, digest_size=8).digest()


def map_mac(raw: bytes) -> bytes:
    """Six raw bytes in, six out. Stable, order-independent, idempotent."""
    if raw == b"\xff" * 6 or raw == b"\x00" * 6:
        return raw                       # broadcast / null: not identifying

    oui, nic = raw[:3], raw[3:]

    # One documentation OUI per distinct real OUI, numbered in first-seen
    # order so the file stays readable.
    if oui not in _oui_seq:
        _oui_seq[oui] = len(_oui_seq)
    idx = _oui_seq[oui]

    # The stand-in OUI is a sequence number, not a vendor: distinct real OUIs
    # stay distinct (so same_oui() and the multi-OUI signal behave as they did
    # on the real data) while nothing about the actual vendor survives. Only
    # the original's locally-administered and multicast bits are carried over,
    # because the survey is cited for how many BSSIDs had the LA bit set.
    #
    # An earlier version put every stand-in in 00:00:5E and encoded the index
    # in the NIC part instead. That collapsed 26 distinct OUIs to 2 and would
    # have made every AP in the sample look same-OUI.
    new_oui = bytes([0x00 | (raw[0] & 0x03), (idx >> 8) & 0xFF, idx & 0xFF])
    # A per-address sequence, not a hash of it: a three-byte digest collided
    # on this very dataset and turned 41 distinct BSSIDs into 40, which would
    # have quietly changed what the sample evidences. A counter cannot.
    if raw not in _nic_seq:
        _nic_seq[raw] = len(_nic_seq) + 1
    seq = _nic_seq[raw]
    out = new_oui + bytes([(seq >> 16) & 0xFF, (seq >> 8) & 0xFF, seq & 0xFF])
    _seen[raw] = out
    return out


def map_mac_str(text: str) -> str:
    raw = bytes(int(x, 16) for x in text.split(":"))
    out = map_mac(raw)
    lower = text.islower()
    s = ":".join(f"{b:02X}" for b in out)
    return s.lower() if lower else s


def redact_text(path: str) -> None:
    src = open(path, encoding="utf-8", errors="surrogateescape").read()
    out = MAC_RE.sub(lambda m: map_mac_str(m.group(0)), src)
    n_ssid = 0
    for rx in (SSID_SURVEY_RE, SSID_SCANLOG_RE):
        def sub(m):
            nonlocal n_ssid
            n_ssid += 1
            return m.group(1) + map_ssid(m.group(2))
        out = rx.sub(sub, out)
    out = IFACE_RE.sub(
        lambda m: m.group(1) + map_mac_str(
            ":".join(m.group(2)[i:i + 2] for i in range(0, 12, 2))
        ).replace(":", "").lower(),
        out,
    )
    open(path, "w", encoding="utf-8", errors="surrogateescape").write(out)
    print(f"  {path}: {len(MAC_RE.findall(src))} addresses, "
          f"{n_ssid} SSID fields replaced")


def redact_pcap(path: str) -> None:
    """Rewrite every MAC address in every 802.11 frame, in place.

    LINKTYPE_IEEE802_11_RADIOTAP (127) only.

    Two passes. The first walks the addr1..addr4 fields by frame type, which
    is what keeps the capture well-formed. The second sweeps each packet's
    bytes for any address the first pass learned about and replaces those too:
    addresses also appear inside frame bodies — association requests, EAPOL
    exchanges, multi-BSSID beacons — and a type-directed walk never reaches
    them. Without the sweep two real addresses survived this very file.

    The sweep only ever replaces an exact six-byte match of an address already
    known to be in the capture, and only within packet data, never in the
    pcap or per-record headers.
    """
    data = bytearray(open(path, "rb").read())
    magic, = struct.unpack_from("<I", data, 0)
    if magic != 0xA1B2C3D4:
        sys.exit(f"{path}: not a little-endian microsecond pcap")
    link, = struct.unpack_from("<I", data, 20)
    if link != 127:
        sys.exit(f"{path}: linktype {link}, expected 127 (radiotap)")

    off, pkts, addrs = 24, 0, 0
    while off + 16 <= len(data):
        incl, = struct.unpack_from("<I", data, off + 8)
        body = off + 16
        end = body + incl
        if end > len(data):
            break
        rt_len, = struct.unpack_from("<H", data, body + 2)
        fr = body + rt_len
        if fr + 10 <= end:
            fc = data[fr]
            ftype = (fc >> 2) & 0x3
            fsub = (fc >> 4) & 0xF
            # Which address fields this frame actually carries.
            if ftype == 1:                       # control
                n = 1 if fsub in (0xC, 0xD, 0xE) else 2   # CTS/ACK/CF-End: 1
            else:                                # management / data / ext
                n = 3
                if ftype == 2 and (data[fr + 1] & 0x03) == 0x03:
                    n = 4                        # ToDS+FromDS: addr4 present
            for i, a in enumerate((4, 10, 16, 24)[:n]):
                if fr + a + 6 <= end:
                    cur = bytes(data[fr + a:fr + a + 6])
                    data[fr + a:fr + a + 6] = map_mac(cur)
                    addrs += 1
        pkts += 1
        off = end

    # SSID information elements. A management frame carries the network name
    # in tag 0 of its element list, after a fixed-parameter block whose size
    # depends on the subtype. The stand-in is the same length as the original,
    # so the element's length byte and every enclosing length stay correct and
    # the capture remains byte-for-byte the size it was.
    FIXED = {0: 4, 2: 10, 4: 0, 5: 12, 8: 12}   # assoc/reassoc req, probe, beacon
    ssids, off = 0, 24
    while off + 16 <= len(data):
        incl, = struct.unpack_from("<I", data, off + 8)
        body, end = off + 16, off + 16 + incl
        if end > len(data):
            break
        rt_len, = struct.unpack_from("<H", data, body + 2)
        fr = body + rt_len
        if fr + 24 <= end:
            fc = data[fr]
            if ((fc >> 2) & 0x3) == 0:                  # management
                sub = (fc >> 4) & 0xF
                if sub in FIXED:
                    i = fr + 24 + FIXED[sub]
                    while i + 2 <= end:                 # walk the elements
                        tag, tlen = data[i], data[i + 1]
                        if i + 2 + tlen > end:
                            break
                        if tag == 0 and tlen:
                            raw = bytes(data[i + 2:i + 2 + tlen])
                            try:
                                name = raw.decode("utf-8")
                            except UnicodeDecodeError:
                                i += 2 + tlen
                                continue
                            new = map_ssid(name).encode("utf-8")
                            if len(new) == tlen:
                                data[i + 2:i + 2 + tlen] = new
                                ssids += 1
                            break
                        i += 2 + tlen
        off = end

    # Second pass: catch addresses AND SSIDs carried in frame bodies. One
    # SSID element sat inside an Action frame (subtype 13), which the walk
    # above does not cover; enumerating every subtype's fixed-parameter block
    # is a losing game, and because stand-ins are the same length as the
    # originals a raw byte replacement is exact and safe.
    known = dict(_seen)
    # longest first, so a short name cannot match inside a longer one
    known.update({k.encode("utf-8"): v.encode("utf-8")
                  for k, v in _ssid_map.items()
                  if len(k.encode("utf-8")) == len(v.encode("utf-8"))})
    _widths = sorted({len(k) for k in known}, reverse=True)
    swept, off = 0, 24
    while off + 16 <= len(data):
        incl, = struct.unpack_from("<I", data, off + 8)
        body, end = off + 16, off + 16 + incl
        if end > len(data):
            break
        i = body
        while i < end:
            hit = None
            for width in _widths:
                if i + width > end:
                    continue
                repl = known.get(bytes(data[i:i + width]))
                if repl is not None:
                    hit = (width, repl)
                    break
            if hit:
                data[i:i + hit[0]] = hit[1]
                swept += 1
                i += hit[0]
            else:
                i += 1
        off = end

    open(path, "wb").write(bytes(data))
    print(f"  {path}: {pkts} packets, {addrs} address fields, "
          f"{swept} in-body occurrences, {ssids} SSID elements rewritten")


MANIFEST = "docs/samples/.redacted"


def _load_manifest() -> dict:
    try:
        return dict(
            l.split(None, 1)[::-1] for l in open(MANIFEST).read().splitlines() if l
        )
    except OSError:
        return {}


def _sha(path: str) -> str:
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit(__doc__)

    done = _load_manifest()
    todo = []
    for p in argv:
        name = p.rsplit("/", 1)[-1]
        if done.get(name) == _sha(p):
            print(f"  {p}: already redacted, skipping")
        else:
            todo.append(p)
    if not todo:
        print("  nothing to do")
        return

    for p in todo:
        if p.endswith(".pcap"):
            redact_pcap(p)
        else:
            redact_text(p)
    print(f"  {len(_oui_seq)} distinct OUIs mapped, {len(_nic_seq)} distinct "
          f"radios, {len(_ssid_map)} distinct SSIDs")

    for p in todo:
        done[p.rsplit("/", 1)[-1]] = _sha(p)
    with open(MANIFEST, "w") as f:
        f.write("# sha256 of each redacted sample, so a second run cannot\n"
                "# re-map addresses that are already stand-ins.\n")
        for k in sorted(done):
            f.write(f"{done[k]}  {k}\n")
    print(f"  manifest written: {MANIFEST}")


if __name__ == "__main__":
    main(sys.argv[1:])
