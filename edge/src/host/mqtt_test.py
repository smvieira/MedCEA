#!/usr/bin/env python3
"""Send one test message (msg_type TS, tag _test) to the broker AS a board.

The host side of "is this board's path to the platform alive?": the wizard's
"Send test message" button and `flash-device.sh --send-test <dns_name>` run this
with the board's provisioned record (edge/provisioned/<dns>.json). It connects
with the board's OWN credential, over the boards' TLS listener, and publishes on
the topic the board itself would use, so a message that arrives proves the
credential, its ACL row, the TLS name and the ingest flow together — and one that
does not says which of them refused (CONNACK's code, a missing PUBACK, the TLS
check).

    mqtt_test.py --record PATH --host HOST --port PORT --tls-name NAME --ca PATH \\
                 --source wizard|cli [--note TEXT] [--timeout SECONDS]

stdout is exactly one JSON line: {"ok":true,"topic":…,"client_id":…,"timestamp":…,
"msg_type":"TS"} (exit 0), or {"ok":false,"error":…} (exit 1: the broker or the
network refused; exit 2: usage, or a record this cannot send as). Nothing else is
printed, on either stream.

The record holds the board's broker password, Wi-Fi PSK and WebREPL password in
plain text (mode 600). None of them is taken on argv (any account can read
/proc/<pid>/cmdline), and none is printed: every error text that leaves this
module goes through _redact() with the record's secrets first.

Stdlib only, MQTT 3.1.1, one connection: CONNECT (clean session) → CONNACK →
PUBLISH QoS 1 → PUBACK → DISCONNECT. QoS 1 because a PUBACK is the broker saying
it took the message; Mosquitto drops a publish its ACL refuses silently and still
acknowledges it, so "sent" means accepted by the broker, not stored — the MQTT
Explorer (tag _test) or the measurement table is where it shows up.
"""

import argparse
import datetime
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import time

ROLES = ("SENSE", "CONTROL")
SOURCES = ("wizard", "cli")
TEST_TAG = "_test"
KEEPALIVE = 30
NOTE_MAX = 200
TIMEOUT_MAX = 120

# CONNACK return codes, MQTT 3.1.1 §3.2.2.3. 5 is what Mosquitto answers a
# credential it does not know (a board removed, or re-onboarded since the record).
CONNACK_RC = {
    1: "unacceptable protocol version",
    2: "identifier rejected",
    3: "server unavailable",
    4: "bad user name or password",
    5: "not authorised",
}

# A topic segment the record supplies: no wildcard or separator may come through
# a unit or zone code (the database's code CHECK is [A-Za-z0-9_-], but a record is
# a file on disk).
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAC_HEX_RE = re.compile(r"^[0-9a-f]{12}$")


class UsageError(Exception):
    """The arguments or the record: nothing was sent (exit 2)."""


class SendError(Exception):
    """The network, TLS or the broker refused: nothing was confirmed (exit 1)."""


# ---- the record --------------------------------------------------------------
def _secrets_of(record):
    """Every secret a provisioned record may hold, for _redact()."""
    out = []
    if isinstance(record, dict):
        mq = record.get("mqtt")
        if isinstance(mq, dict):
            out.append(mq.get("password"))
        out += [record.get("wifi_psk"), record.get("webrepl_password")]
    return [s for s in out if isinstance(s, str) and s]


def _redact(text, secret_list):
    text = str(text)
    # Longest first, so a secret that contains another is not half-redacted.
    for s in sorted(secret_list, key=len, reverse=True):
        text = text.replace(s, "***")
    return text


def load_record(path):
    """The provisioned record as a dict. Its content never reaches an error text."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except OSError as e:
        raise UsageError("cannot read the record %s (%s)" % (path, e.strerror or type(e).__name__))
    try:
        rec = json.loads(raw)
    except ValueError:
        # json's message quotes no content, but say less anyway: the file is a secret.
        raise UsageError("the record %s is not valid JSON" % path)
    if not isinstance(rec, dict):
        raise UsageError("the record %s is not a JSON object" % path)
    return rec


def _mac_forms(mac):
    """(device_id, mac) as the board writes them: config.py's device_id is
    hexlify(machine.unique_id()) — on an ESP32 the base MAC, lower-case hex with no
    separators, = medcea.device.serial_number — and the HB/TS `mac` is
    hexlify(WLAN.config("mac"), ":"), lower case with colons. The record has what
    esptool printed (aa:bb:…)."""
    if not isinstance(mac, str):
        return None
    hexed = re.sub(r"[:\-.]", "", mac.strip().lower())
    if not _MAC_HEX_RE.match(hexed):
        return None
    return hexed, ":".join(hexed[i:i + 2] for i in range(0, 12, 2))


def check_record(rec):
    """What the message needs, from the record; UsageError when it cannot be sent as."""
    if rec.get("state") == "UNREGISTERED":
        raise UsageError("the board is unregistered: it has no broker credential or slot")
    role = rec.get("role")
    if role not in ROLES:
        raise UsageError("the record's role is %r, not SENSE or CONTROL" % (role,))
    mq = rec.get("mqtt")
    if not isinstance(mq, dict):
        raise UsageError("the record has no mqtt credential (re-onboard the board)")
    user, pw = mq.get("username"), mq.get("password")
    if not (isinstance(user, str) and user and isinstance(pw, str) and pw):
        raise UsageError("the record has no mqtt username or password (re-onboard the board)")
    root = mq.get("topic_root")
    if not (isinstance(root, str) and _SEGMENT_RE.match(root)):
        raise UsageError("the record has no usable mqtt.topic_root")
    unit, zone = rec.get("unit_code"), rec.get("zone_code")
    for name, val in (("unit_code", unit), ("zone_code", zone)):
        if not (isinstance(val, str) and _SEGMENT_RE.match(val)):
            raise UsageError("the record's %s is missing or not a topic segment" % name)
    dns = rec.get("hostname")
    if not (isinstance(dns, str) and re.match(r"^[a-z0-9][a-z0-9-]{0,31}$", dns)):
        raise UsageError("the record has no usable hostname")
    forms = _mac_forms(rec.get("mac"))
    if forms is None:
        raise UsageError("the record has no usable mac")
    return {"role": role, "user": user, "password": pw, "root": root, "unit": unit,
            "zone": zone, "dns": dns, "device_id": forms[0], "mac": forms[1]}


def _flashed_key(rec, path):
    # flashed_at is ISO 8601 UTC (sorts as text); a record without one counts by its file time.
    at = rec.get("flashed_at")
    if isinstance(at, str) and at:
        return at
    try:
        return "%020.6f" % os.path.getmtime(path)
    except OSError:
        return ""


def superseded_by(path, rec):
    """The name of a later record of the same board in the same folder, or None.

    A board that moves to another slot, or is onboarded again under another name,
    leaves its old record behind; the old name's broker credential was retired with
    the move, so a test sent as it is refused by the broker. Same board = same MAC;
    later = flashed later. Only names are compared and returned, never content."""
    mine = _mac_forms(rec.get("mac"))
    if mine is None:
        return None
    me = os.path.abspath(path)
    key = _flashed_key(rec, path)
    folder = os.path.dirname(me)
    newer = None
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return None
    for name in names:
        other = os.path.join(folder, name)
        if not name.endswith(".json") or other == me:
            continue
        try:
            with open(other, encoding="utf-8") as f:
                o = json.load(f)
        except (OSError, ValueError):
            continue
        if not isinstance(o, dict) or _mac_forms(o.get("mac")) != mine:
            continue
        k = _flashed_key(o, other)
        if k > key and (newer is None or k > newer[0]):
            newer = (k, name[:-5])
    return newer and newer[1]


def topic_of(info):
    """The board's own topic for a test: a CONTROL board may write only
    control_setpoint/# (its ACL), and Node-RED takes TS only from exactly
    <root>/<unit>/<zone>/<sense|control_setpoint>/_test."""
    base = "%s/%s/%s" % (info["root"], info["unit"], info["zone"])
    leaf = "control_setpoint" if info["role"] == "CONTROL" else "sense"
    return "%s/%s/%s" % (base, leaf, TEST_TAG)


def timestamp(now=None):
    """ef.get_timestamp()'s format, 'YYYY-MM-DD HH:MM:SS'. The board's clock is
    set by ntptime, i.e. UTC, so the host's is UTC too."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return now.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def firmware_of(rec):
    """The board's os.uname().release ('1.29.0') from the record's `micropython`,
    which is sys.version ('3.4.0; MicroPython v1.29.0 on 2026-08-24'): the field
    means the same from either sender. A value of another shape passes as it is."""
    fw = rec.get("micropython")
    if not (isinstance(fw, str) and fw):
        return None
    m = re.search(r"MicroPython v(\d+\.\d+(?:\.\d+)?\S*)", fw)
    return m.group(1) if m else fw


def build_payload(rec, info, source, note=None, now=None):
    """The TS message: a reading's metadata except "sensor" (cea_sense.Board._message),
    the board's ip and mac, and what sent it. `sent_from: host` marks it as not the board's own."""
    msg = {
        "unit_code": info["unit"],
        "zone_code": info["zone"],
        "msg_type": "TS",
        "timestamp": timestamp(now),
        "device_id": info["device_id"],
        "device_dns": info["dns"],
        "tag": TEST_TAG,
        # The board's address when it was onboarded: the host cannot know today's.
        "ip": rec.get("ip_at_provision") or None,
        "mac": info["mac"],
        "source": source,
        "firmware": firmware_of(rec),
        "sent_from": "host",
    }
    if note is not None:
        msg["note"] = note
    return msg


def check_note(note):
    if note is None:
        return None
    # No quote characters, as the board's health text (cea_sense._err): Node-RED's
    # INSERT splices the message into a quoted SQL literal as it is.
    if (len(note) > NOTE_MAX or any(c in note for c in "\r\n'\"")
            or not note.isprintable()):
        raise UsageError("the note must be one printable line of at most %d characters, "
                         "without quote characters" % NOTE_MAX)
    return note


# ---- MQTT 3.1.1, just what one publish needs -----------------------------------
def _str(s):
    b = s.encode("utf-8")
    return struct.pack("!H", len(b)) + b


def _remaining_length(n):
    out = bytearray()
    while True:
        byte, n = n % 128, n // 128
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _packet(first, body):
    return bytes([first]) + _remaining_length(len(body)) + body


def connect_packet(client_id, user, password, keepalive=KEEPALIVE):
    # Protocol "MQTT" level 4; flags: user name, password, clean session.
    var = _str("MQTT") + bytes([4, 0xC2]) + struct.pack("!H", keepalive)
    return _packet(0x10, var + _str(client_id) + _str(user) + _str(password))


def publish_packet(topic, payload, packet_id):
    return _packet(0x32, _str(topic) + struct.pack("!H", packet_id) + payload)  # QoS 1


DISCONNECT = b"\xe0\x00"


def _recv_exact(sock, n, deadline, waiting_for):
    buf = b""
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise SendError("timed out waiting for %s" % waiting_for)
        sock.settimeout(left)
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, TimeoutError):
            raise SendError("timed out waiting for %s" % waiting_for)
        if not chunk:
            raise SendError("the broker closed the connection before %s" % waiting_for)
        buf += chunk
    return buf


def read_packet(sock, deadline, waiting_for):
    """(packet type, body) of the next packet."""
    first = _recv_exact(sock, 1, deadline, waiting_for)[0]
    length, mult = 0, 1
    for _ in range(4):
        b = _recv_exact(sock, 1, deadline, waiting_for)[0]
        length += (b & 0x7F) * mult
        mult *= 128
        if not b & 0x80:
            break
    else:
        raise SendError("malformed packet from the broker")
    return first >> 4, _recv_exact(sock, length, deadline, waiting_for) if length else b""


def _tls_context(ca):
    try:
        ctx = ssl.create_default_context(cafile=ca)
    except (OSError, ssl.SSLError) as e:
        raise UsageError("cannot read the CA file %s (%s)" % (ca, getattr(e, "strerror", None)
                                                              or type(e).__name__))
    # The platform CA (deploy-infra.sh, .ca/) has no keyUsage extension and the
    # broker's certificate no authorityKeyIdentifier. Browsers, curl and the boards
    # accept them; Python 3.13's default VERIFY_X509_STRICT does not. Chain, expiry
    # and the name are still verified (as tests/iam_signin_flow.py does).
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def send_test(record, host, port, tls_name, ca, source, note=None, timeout=10):
    """Publish one TS message as the record's board. Returns the success dict, or
    raises UsageError (nothing sent: arguments or record) or SendError (refused or
    unconfirmed). Neither error's text holds a secret of the record."""
    if source not in SOURCES:
        raise UsageError("--source must be one of %s" % ", ".join(SOURCES))
    note = check_note(note)
    info = check_record(record)
    topic = topic_of(info)
    msg = build_payload(record, info, source, note)
    body = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    client_id = "%s-test-%s" % (info["dns"], secrets.token_hex(2))
    ctx = _tls_context(ca)
    deadline = time.monotonic() + timeout
    phase = "the connection to %s:%s" % (host, port)
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except (socket.timeout, TimeoutError):
        raise SendError("timed out connecting to %s:%s" % (host, port))
    except OSError as e:
        raise SendError("cannot connect to %s:%s (%s)" % (host, port, e.strerror or type(e).__name__))
    try:
        try:
            sock = ctx.wrap_socket(raw, server_hostname=tls_name)
        except ssl.SSLCertVerificationError as e:
            raise SendError("TLS: the broker's certificate was refused (%s)"
                            % (e.verify_message or "verification failed"))
        except (ssl.SSLError, OSError) as e:
            raise SendError("TLS handshake failed (%s)" % (getattr(e, "reason", None) or type(e).__name__))
        raw = sock
        phase = "CONNACK"
        sock.sendall(connect_packet(client_id, info["user"], info["password"]))
        ptype, pbody = read_packet(sock, deadline, "CONNACK")
        if ptype != 2 or len(pbody) != 2:
            raise SendError("the broker answered CONNECT with packet type %d, not CONNACK" % ptype)
        rc = pbody[1]
        if rc:
            raise SendError("the broker refused the board's credential: %s"
                            % CONNACK_RC.get(rc, "return code %d" % rc))
        packet_id = secrets.randbelow(0xFFFF) + 1
        phase = "PUBACK"
        sock.sendall(publish_packet(topic, body, packet_id))
        while True:
            ptype, pbody = read_packet(sock, deadline, "PUBACK")
            if ptype == 4 and len(pbody) == 2 and struct.unpack("!H", pbody)[0] == packet_id:
                break
            if ptype == 3:   # an offline message for a subscription: not ours, skip
                continue
            raise SendError("the broker answered PUBLISH with packet type %d, not PUBACK" % ptype)
        try:
            sock.sendall(DISCONNECT)
        except OSError:
            pass             # acknowledged already: a lost DISCONNECT changes nothing
    except OSError as e:
        raise SendError("connection lost waiting for %s (%s)" % (phase, e.strerror or type(e).__name__))
    finally:
        try:
            raw.close()
        except OSError:
            pass
    return {"ok": True, "topic": topic, "client_id": client_id,
            "timestamp": msg["timestamp"], "msg_type": "TS"}


# ---- the command ----------------------------------------------------------------
class _Parser(argparse.ArgumentParser):
    """A usage error is the same one JSON line on stdout as any other failure."""
    def error(self, message):
        _emit({"ok": False, "error": "usage: " + message})
        sys.exit(2)


def _emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _port(v):
    n = int(v)
    if not 0 < n < 65536:
        raise ValueError(v)
    return n


def _timeout(v):
    n = float(v)
    if not 0 < n <= TIMEOUT_MAX:
        raise ValueError(v)
    return n


def main(argv=None):
    p = _Parser(prog="mqtt_test.py", description="Send one TS test message as a provisioned board.")
    p.add_argument("--record", required=True, help="edge/provisioned/<dns>.json")
    p.add_argument("--host", required=True)
    p.add_argument("--port", required=True, type=_port)
    p.add_argument("--tls-name", required=True, help="the name in the broker's certificate")
    p.add_argument("--ca", required=True, help="the platform CA (.ca/ca.crt)")
    p.add_argument("--source", required=True, choices=SOURCES)
    p.add_argument("--note", help="one line, at most %d characters, no quotes" % NOTE_MAX)
    p.add_argument("--timeout", type=_timeout, default=10.0,
                   help="seconds for the whole exchange (default 10, at most %d)" % TIMEOUT_MAX)
    a = p.parse_args(argv)
    known = []
    try:
        rec = load_record(a.record)
        known = _secrets_of(rec)
        later = superseded_by(a.record, rec)
        if later:
            raise UsageError("this record is superseded: the same board was onboarded later as %s "
                             "(moved or re-onboarded; its old credential is retired). Send as %s."
                             % (later, later))
        result = send_test(rec, a.host, a.port, a.tls_name, a.ca, a.source,
                           note=a.note, timeout=a.timeout)
    except UsageError as e:
        _emit({"ok": False, "error": _redact(e, known)})
        return 2
    except SendError as e:
        _emit({"ok": False, "error": _redact(e, known)})
        return 1
    except Exception as e:   # never a traceback: it could quote the record
        _emit({"ok": False, "error": _redact("unexpected %s: %s" % (type(e).__name__, e), known)})
        return 1
    _emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
