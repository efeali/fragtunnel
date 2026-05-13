import getopt
import socket
import struct
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

BUFFER_SIZE = 8192
FRAGMENT_SIZE = 1024
WORKERS = 8
TARGET_FLUSH_IDLE_MS = 50
LONG_POLL_S = 1.0
LISTEN_BACKLOG = 1024
HEADER_SIZE = 8

SECRET_KEY = b""
ENCRYPTED_TUNNEL = False
VERBOSE = False
FRAGMENT_SIZE_EXPLICIT = False  # user passed -F → skip startup probe
FAST_CLOSE = False              # -f → SO_LINGER timeout=0 on burnout sockets (RST close, no TIME_WAIT)

# Startup-probe parameters
PROBE_STEP = 1024
PROBE_MAX = 16384
PROBE_TIMEOUT_S = 3.0

TUNNEL_SERVER_IP, TUNNEL_SERVER_PORT, TARGET_IP, TARGET_PORT = "", 0, "", 0
LOCAL_PORT, BIND_IP = 0, ""

# Wire opcodes
OP_FRAG = 0x01    # seq = fragment index, payload = data
OP_EOD = 0x02     # seq = total fragment count, no payload
OP_ACK = 0x03
OP_ERR = 0x04
OP_TARGET = 0x05  # payload = "ip:port" UTF-8
OP_POLL = 0x06    # client asks server for next outbound frame
OP_WAIT = 0x07    # server: no outbound data yet
OP_DONE = 0x08    # server: outbound batch finished, total in seq
OP_PROBE = 0x09           # client->server: payload of varying size; server ACKs
OP_SET_FRAG_SIZE = 0x0A   # client->server: seq = chosen fragment size; server ACKs

OPCODE_NAMES = {
    OP_FRAG: "FRAG", OP_EOD: "EOD", OP_ACK: "ACK", OP_ERR: "ERR",
    OP_TARGET: "TARGET", OP_POLL: "POLL", OP_WAIT: "WAIT", OP_DONE: "DONE",
    OP_PROBE: "PROBE", OP_SET_FRAG_SIZE: "SET_FRAG_SIZE",
}


def xor_data(original, key):
    key = key.encode() if isinstance(key, str) else key
    extended_key = key * (len(original) // len(key)) + key[:len(original) % len(key)]
    return bytes(b1 ^ b2 for b1, b2 in zip(original, extended_key))


def encrypt_data(data):
    return xor_data(data, SECRET_KEY)


def log(message):
    if VERBOSE:
        print(message)


def set_nodelay(sock):
    """Disable Nagle for the small-frame-per-session traffic pattern."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


def set_burnout_opts(sock):
    """Burnout sockets: TCP_NODELAY plus (when -f is set) SO_LINGER timeout=0
    so close() sends RST instead of FIN, skipping TIME_WAIT. NOT for persistent
    sockets (user/target) — RST can truncate unread data."""
    set_nodelay(sock)
    if FAST_CLOSE:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack("ii", 1, 0))
        except OSError:
            pass


def recv_exact(sock, n):
    """Read exactly n bytes from sock, or return None on EOF."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


@dataclass
class Frame:
    opcode: int
    seq: int = 0
    payload: bytes = b""

    def pack(self):
        """Serialize and (if enabled) encrypt the entire frame as one buffer."""
        header = struct.pack(">BBHI", self.opcode, 0, len(self.payload), self.seq)
        buf = header + self.payload
        if ENCRYPTED_TUNNEL:
            buf = encrypt_data(buf)
        return buf

    @classmethod
    def recv(cls, sock):
        """Read one frame from sock; returns None on connection close/error."""
        header_raw = recv_exact(sock, HEADER_SIZE)
        if header_raw is None:
            return None
        if ENCRYPTED_TUNNEL:
            # XOR the header with key starting at offset 0
            header_plain = xor_data(header_raw, SECRET_KEY)
        else:
            header_plain = header_raw
        opcode, _, length, seq = struct.unpack(">BBHI", header_plain)
        payload = b""
        if length > 0:
            payload_raw = recv_exact(sock, length)
            if payload_raw is None:
                return None
            if ENCRYPTED_TUNNEL:
                # Continue keystream after the 8-byte header
                key = SECRET_KEY
                offset = HEADER_SIZE % len(key)
                shifted_key = key[offset:] + key[:offset]
                payload = xor_data(payload_raw, shifted_key)
            else:
                payload = payload_raw
        return cls(opcode=opcode, seq=seq, payload=payload)


def send_frame(sock, frame):
    sock.sendall(frame.pack())


def chunk_into_fragments(data, size):
    return [data[i:i + size] for i in range(0, len(data), size)]


class TunnelSession:
    """Per-local-app session state. Replaces shared globals."""

    def __init__(self, workers):
        self.workers = workers
        self.target_set = False
        self.target_ip = ""
        self.target_port = 0
        self.target_sock = None
        self.shutdown = threading.Event()

        # Inbound: fragments arriving from tunnel client, to be reassembled and
        # forwarded to target (server side) or to local app (client side).
        self.inbound_lock = threading.Lock()
        self.inbound = {}            # dict[seq] = payload
        self.inbound_total = None    # int when EOD arrived
        self.inbound_complete = threading.Event()

        # Outbound (server side): fragments built from target responses, served
        # to tunnel client via POLL. Uses a Condition so target_reader can
        # notify waiting POLL handlers (long-polling).
        self.outbound_cond = threading.Condition()
        self.outbound = []                       # list[bytes] indexed by seq
        self.outbound_total = None               # int when batch flushed/EOF
        self.outbound_next_seq_to_serve = 0
        self.outbound_last_append_ms = 0         # for idle-flush timer


def open_tunnel_socket():
    """Open a fresh TCP socket to the tunnel server (used per burnout session)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    set_burnout_opts(s)
    s.connect((TUNNEL_SERVER_IP, TUNNEL_SERVER_PORT))
    return s


def send_one_frame(frame, expect_response=True, timeout=None):
    """Open burnout socket, send one frame, optionally read response, close.

    If `timeout` is given, applies it to send and recv so a firewall silently
    dropping the session manifests as socket.timeout rather than hanging.
    """
    sock = open_tunnel_socket()
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        send_frame(sock, frame)
        if expect_response:
            return Frame.recv(sock)
        return None
    except (socket.timeout, OSError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def send_fragments_parallel(data, executor):
    """Send `data` as parallel FRAG frames + final EOD. Returns True on success.

    Each fragment travels in its own TCP session (burnout pattern preserved).
    Synchronous: returns only after all FRAGs and the EOD have been ACKed.
    """
    fragments = chunk_into_fragments(data, FRAGMENT_SIZE)
    total = len(fragments)
    if total == 0:
        return True

    futures = []
    for seq, frag in enumerate(fragments):
        f = executor.submit(send_one_frame, Frame(OP_FRAG, seq, frag))
        futures.append(f)

    ok = True
    for f in as_completed(futures):
        try:
            resp = f.result()
        except Exception as e:
            log("FRAG send failed: %s" % e)
            ok = False
            continue
        if resp is None or resp.opcode != OP_ACK:
            log("FRAG missing ACK: %s" % (resp,))
            ok = False

    if not ok:
        return False

    eod_resp = send_one_frame(Frame(OP_EOD, total, b""))
    if eod_resp is None or eod_resp.opcode != OP_ACK:
        log("EOD missing ACK")
        return False
    return True


def poll_once():
    """One POLL round trip. Returns the response Frame (FRAG / WAIT / DONE) or None."""
    return send_one_frame(Frame(OP_POLL, 0, b""))


def poll_loop(session, local_connection, executor):
    """Tunnel-client side: maintain N parallel POLLs, reassemble, deliver to local app."""
    client_inbound = {}
    client_inbound_total = None

    while not session.shutdown.is_set():
        futures = [executor.submit(poll_once) for _ in range(session.workers)]
        # Always drain every future fully, even after shutdown — the in-flight
        # POLLs may already have been served FRAGs on the wire; abandoning
        # them would lose that data for the next local connection.
        for f in as_completed(futures):
            try:
                resp = f.result()
            except Exception as e:
                log("POLL failed: %s" % e)
                continue
            if resp is None:
                continue
            if resp.opcode == OP_FRAG:
                client_inbound[resp.seq] = resp.payload
            elif resp.opcode == OP_DONE:
                client_inbound_total = resp.seq
            elif resp.opcode == OP_WAIT:
                pass
            elif resp.opcode == OP_ERR:
                log("POLL got ERR")
                session.shutdown.set()
                return
            else:
                pass  # ignore unexpected opcodes

            # Eager delivery: as soon as one batch is complete, ship it before
            # trailing long-pollers in this same iteration return FRAGs of the
            # NEXT batch (which would overwrite this batch's frags in the dict).
            if (client_inbound_total is not None
                    and len(client_inbound) >= client_inbound_total):
                try:
                    joined = b"".join(client_inbound[i] for i in range(client_inbound_total))
                except KeyError as e:
                    log("Reassembly hole at seq %s; aborting batch" % e)
                    client_inbound = {}
                    client_inbound_total = None
                    continue
                try:
                    local_connection.sendall(joined)
                    log("Delivered %d bytes to local app" % len(joined))
                except OSError as e:
                    log("Local connection write failed: %s" % e)
                    session.shutdown.set()
                    return
                client_inbound = {}
                client_inbound_total = None


def handle_local_client(local_connection, session):
    """Drive one local-app session: fragment outbound, poll for inbound."""
    send_executor = ThreadPoolExecutor(max_workers=session.workers,
                                       thread_name_prefix="frag-send")
    poll_executor = ThreadPoolExecutor(max_workers=session.workers,
                                       thread_name_prefix="frag-poll")
    poll_thread = threading.Thread(
        target=poll_loop,
        args=(session, local_connection, poll_executor),
        daemon=True,
    )
    poll_thread.start()

    try:
        local_connection.setblocking(1)
        while not session.shutdown.is_set():
            try:
                data = local_connection.recv(BUFFER_SIZE)
            except OSError as e:
                log("Local recv error: %s" % e)
                break
            if not data:
                break
            if not send_fragments_parallel(data, send_executor):
                log("Outbound batch failed")
                break
    except KeyboardInterrupt:
        print("Local client terminated by user")
    except Exception as e:
        print("Exception: %s" % str(e))
        traceback.print_tb(e.__traceback__)
    finally:
        session.shutdown.set()
        # Wait for poll_loop to drain its in-flight long-polls; otherwise it
        # keeps stealing fragments after this handler returns and the next
        # local connection would lose its server-side outbound data.
        poll_thread.join(timeout=LONG_POLL_S + 1.0)
        send_executor.shutdown(wait=False, cancel_futures=True)
        poll_executor.shutdown(wait=False, cancel_futures=True)
        try:
            local_connection.close()
        except OSError:
            pass


def probe_fragment_size():
    """Walk fragment sizes upward in 1024-byte steps until the tunnel server
    stops responding (firewall cap reached) or we hit PROBE_MAX. Sets
    global FRAGMENT_SIZE to the largest size that round-tripped and tells
    the tunnel server to use the same size for its outbound chunking via
    OP_SET_FRAG_SIZE. Returns False on fatal failure (cannot reach server)."""
    global FRAGMENT_SIZE
    import os
    print("Probing maximum fragment size (1024..%d, step 1024)..." % PROBE_MAX)
    max_ok = 0
    for size in range(PROBE_STEP, PROBE_MAX + 1, PROBE_STEP):
        payload = os.urandom(size)
        resp = send_one_frame(Frame(OP_PROBE, 0, payload), timeout=PROBE_TIMEOUT_S)
        if resp is not None and resp.opcode == OP_ACK:
            print("  %d bytes: OK" % size)
            max_ok = size
        else:
            print("  %d bytes: FAILED (firewall cap or server unreachable)" % size)
            break

    if max_ok == 0:
        print("Probe failed at %d bytes — even the minimum fragment size doesn't "
              "round-trip.\nIs the tunnel server up? Check -e/--encrypt matches "
              "on both ends." % PROBE_STEP)
        return False

    print("Probed max fragment size: %d bytes" % max_ok)
    FRAGMENT_SIZE = max_ok

    # Tell the server to use this size for its outbound (target -> local-app) chunking.
    resp = send_one_frame(Frame(OP_SET_FRAG_SIZE, max_ok, b""), timeout=PROBE_TIMEOUT_S)
    if resp is not None and resp.opcode == OP_ACK:
        print("Server acknowledged fragment size %d" % max_ok)
    else:
        print("Warning: server did not ACK SET_FRAG_SIZE; its outbound responses "
              "may still use the default fragment size.")
    return True


def local_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", LOCAL_PORT))
    s.listen(LISTEN_BACKLOG)
    print("Local server listening on port %d" % LOCAL_PORT)

    try:
        while True:
            conn, addr = s.accept()
            set_nodelay(conn)
            log("Local connection from %s" % (addr,))

            session = TunnelSession(workers=WORKERS)
            session.target_ip = TARGET_IP
            session.target_port = TARGET_PORT

            # Handshake: tell tunnel server which target to connect to.
            target_str = "%s:%d" % (TARGET_IP, TARGET_PORT)
            resp = send_one_frame(Frame(OP_TARGET, 0, target_str.encode()))
            if resp is None or resp.opcode != OP_ACK:
                print("Error: target handshake failed (mismatched encryption?)")
                conn.close()
                continue
            session.target_set = True
            log("Target handshake OK")

            # Serialize local connections: the server session is single-tenant
            # (one shared inbound/outbound queue), so concurrent local connections
            # would race for the same outbound fragments and lose data.
            t = threading.Thread(target=handle_local_client,
                                 args=(conn, session), daemon=True)
            t.start()
            t.join()
    except KeyboardInterrupt:
        print("Local server terminated by user")
    except Exception as e:
        print("Exception: %s" % str(e))
        traceback.print_tb(e.__traceback__)
    finally:
        try:
            s.close()
        except OSError:
            pass


def open_target_socket(session):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    set_nodelay(s)
    s.connect((session.target_ip, session.target_port))
    s.settimeout(0.02)
    log("Connected to target server %s:%d" % (session.target_ip, session.target_port))
    return s


def now_ms():
    return int(time.monotonic() * 1000)


def target_reader_thread(session):
    """Read from session.target_sock, chunk into session.outbound, idle-flush boundary."""
    try:
        while not session.shutdown.is_set():
            if session.target_sock is None:
                time.sleep(0.01)
                continue
            data = None
            try:
                data = session.target_sock.recv(BUFFER_SIZE)
            except socket.timeout:
                # Idle tick: if we've appended data and gone quiet, finalize batch
                with session.outbound_cond:
                    has_data = len(session.outbound) > 0
                    fresh = (now_ms() - session.outbound_last_append_ms) >= TARGET_FLUSH_IDLE_MS
                    if has_data and fresh and session.outbound_total is None:
                        session.outbound_total = len(session.outbound)
                        session.outbound_cond.notify_all()
                        log("Flushed outbound batch (idle), total=%d" % session.outbound_total)
                continue
            except OSError as e:
                log("Target recv error: %s" % e)
                break
            if not data:
                # Target closed: mark batch complete with whatever we have
                with session.outbound_cond:
                    if session.outbound_total is None:
                        session.outbound_total = len(session.outbound)
                    session.outbound_cond.notify_all()
                log("Target EOF; outbound_total=%d" % (session.outbound_total or 0))
                break
            # Append fragments
            fragments = chunk_into_fragments(data, FRAGMENT_SIZE)
            with session.outbound_cond:
                # If a previous batch is still being drained (DONE not yet served),
                # extend it; the client will see one bigger batch. But if DONE was
                # already served, we need a fresh batch.
                if (session.outbound_total is not None
                        and session.outbound_next_seq_to_serve >= session.outbound_total):
                    # Previous batch fully served — start a new one.
                    session.outbound = []
                    session.outbound_total = None
                    session.outbound_next_seq_to_serve = 0
                for frag in fragments:
                    session.outbound.append(frag)
                session.outbound_last_append_ms = now_ms()
                session.outbound_cond.notify_all()
    except Exception as e:
        log("target_reader exception: %s" % e)
    finally:
        with session.outbound_cond:
            session.outbound_cond.notify_all()
        session.shutdown.set()


def inbound_reassembler_thread(session):
    """Wait on inbound_complete, join fragments in seq order, send to target."""
    while not session.shutdown.is_set():
        if not session.inbound_complete.wait(timeout=0.5):
            continue
        with session.inbound_lock:
            total = session.inbound_total
            if total is None or len(session.inbound) < total:
                # Spurious wakeup; clear and keep waiting
                session.inbound_complete.clear()
                continue
            try:
                joined = b"".join(session.inbound[i] for i in range(total))
            except KeyError as e:
                log("Reassembly hole at seq %s" % e)
                session.inbound = {}
                session.inbound_total = None
                session.inbound_complete.clear()
                continue
            session.inbound = {}
            session.inbound_total = None
            session.inbound_complete.clear()
        try:
            if session.target_sock is not None:
                session.target_sock.sendall(joined)
                log("Forwarded %d bytes to target" % len(joined))
        except OSError as e:
            log("Target send failed: %s" % e)
            session.shutdown.set()
            return


def handle_tunnel_session_frame(conn, session):
    """Handle one accepted burnout-session connection. Reads one frame, sends one response."""
    try:
        frame = Frame.recv(conn)
        if frame is None:
            return

        if frame.opcode == OP_TARGET:
            handle_target_frame(conn, frame, session)
            return

        # PROBE and SET_FRAG_SIZE run at tunnel-client startup, before any
        # TARGET handshake. They must work without target_set.
        if frame.opcode == OP_PROBE:
            send_frame(conn, Frame(OP_ACK))
            return

        if frame.opcode == OP_SET_FRAG_SIZE:
            global FRAGMENT_SIZE
            if 1 <= frame.seq <= 65535:
                FRAGMENT_SIZE = frame.seq
                log("Server fragment size set to %d" % FRAGMENT_SIZE)
            send_frame(conn, Frame(OP_ACK))
            return

        if not session.target_set:
            send_frame(conn, Frame(OP_ERR))
            return

        if frame.opcode == OP_FRAG:
            with session.inbound_lock:
                session.inbound[frame.seq] = frame.payload
                if (session.inbound_total is not None
                        and len(session.inbound) >= session.inbound_total):
                    session.inbound_complete.set()
            send_frame(conn, Frame(OP_ACK))

        elif frame.opcode == OP_EOD:
            with session.inbound_lock:
                session.inbound_total = frame.seq
                if len(session.inbound) >= session.inbound_total:
                    session.inbound_complete.set()
            send_frame(conn, Frame(OP_ACK))

        elif frame.opcode == OP_POLL:
            handle_poll(conn, session)

        else:
            log("Unexpected opcode in session frame: %s" %
                OPCODE_NAMES.get(frame.opcode, frame.opcode))
            send_frame(conn, Frame(OP_ERR))

    except Exception as e:
        log("session frame handler error: %s" % e)
        traceback.print_tb(e.__traceback__)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def handle_target_frame(conn, frame, session):
    """First-time handshake: resolve target ip:port and connect."""
    try:
        addr = frame.payload.decode()
        ip, port_str = addr.split(":")
        port = int(port_str)
    except Exception:
        print("Error: malformed TARGET frame "
              "(check that both sides use matching -e secret)")
        send_frame(conn, Frame(OP_ERR))
        return

    if session.target_set:
        # Already set; just ACK.
        send_frame(conn, Frame(OP_ACK))
        return

    session.target_ip = ip
    session.target_port = port
    try:
        session.target_sock = open_target_socket(session)
    except OSError as e:
        print("Error: could not connect to target %s:%d: %s" % (ip, port, e))
        send_frame(conn, Frame(OP_ERR))
        return

    session.target_set = True
    threading.Thread(target=target_reader_thread, args=(session,), daemon=True).start()
    threading.Thread(target=inbound_reassembler_thread, args=(session,), daemon=True).start()
    log("Target set to %s:%d; reader+reassembler started" % (ip, port))
    send_frame(conn, Frame(OP_ACK))


def handle_poll(conn, session):
    """Long-poll: serve next outbound frame, DONE, or WAIT after timeout.

    Holds the connection up to LONG_POLL_S waiting for outbound data so the
    client doesn't have to thrash on TCP setup/teardown when nothing's ready.
    """
    deadline = time.monotonic() + LONG_POLL_S
    response = None
    with session.outbound_cond:
        while response is None:
            if session.shutdown.is_set():
                response = Frame(OP_WAIT)
                break
            next_seq = session.outbound_next_seq_to_serve
            total = session.outbound_total
            outbound_len = len(session.outbound)

            if next_seq < outbound_len:
                payload = session.outbound[next_seq]
                session.outbound_next_seq_to_serve += 1
                response = Frame(OP_FRAG, next_seq, payload)
                break

            if total is not None and next_seq >= total:
                response = Frame(OP_DONE, total, b"")
                # Reset for next batch (target may produce more data later)
                session.outbound = []
                session.outbound_total = None
                session.outbound_next_seq_to_serve = 0
                break

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                response = Frame(OP_WAIT)
                break
            session.outbound_cond.wait(timeout=min(remaining, 0.5))

    send_frame(conn, response)


def tunnel_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", TUNNEL_SERVER_PORT))
    s.listen(LISTEN_BACKLOG)

    # Bounded pool: enough headroom so long-polling POLLs don't starve FRAGs.
    # POLLs hold a thread up to LONG_POLL_S; FRAGs return quickly.
    pool_size = max(WORKERS * 4, 64)
    pool = ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix="tunnel-srv")
    print("Tunnel server listening on port %d (pool=%d, backlog=%d)"
          % (TUNNEL_SERVER_PORT, pool_size, LISTEN_BACKLOG))

    session = TunnelSession(workers=WORKERS)

    try:
        while True:
            conn, addr = s.accept()
            set_burnout_opts(conn)
            pool.submit(handle_tunnel_session_frame, conn, session)
    except KeyboardInterrupt:
        print("Tunnel server terminated by user")
    except Exception as e:
        print("Exception: %s" % str(e))
        traceback.print_tb(e.__traceback__)
    finally:
        session.shutdown.set()
        with session.outbound_cond:
            session.outbound_cond.notify_all()
        pool.shutdown(wait=False, cancel_futures=True)
        try:
            s.close()
        except OSError:
            pass


def usage():
    print("\r\nUsage: %s -p port -t target ip:port -T tunnel endpoint ip:port -b bind ip:port -e secret -w workers\r\n"
          % sys.argv[0])
    print("-h --help        help")
    print("-p --port        port to listen for a local app to connect")
    print("-t --target      target's ip:port")
    print("-T --Tunnel to   tunnel server's ip:port")
    print("-b --bind        tunnel server listen ip:port")
    print("-e --encrypt     encrypt/encode tunnel traffic using the secret provided with this flag")
    print("-w --workers     number of parallel fragment workers (default 8)")
    print("-F --frag-size   bytes per fragment (max 65535). If omitted, tunnel")
    print("                 client probes the firewall at startup (1024..16384,")
    print("                 step 1024) and uses the largest size that round-trips.")
    print("                 Explicit -F skips the probe.")
    print("-f --fast-close  SO_LINGER timeout=0 on burnout sockets (RST close,")
    print("                 skips TIME_WAIT — large throughput win on Linux).")
    print("-v --verbose     verbose mode")
    sys.exit(0)


if __name__ == "__main__":
    target, tunnel_endpoint, bind = "", "", ""

    if not len(sys.argv[1:]):
        usage()

    argumentList = sys.argv[1:]
    options = "ht:T:p:b:e:vw:F:f"
    long_options = ["help", "target=", "tunnelTo=", "port=", "bind=",
                    "encrypt=", "verbose", "workers=", "frag-size=", "fast-close"]

    try:
        arguments, values = getopt.getopt(argumentList, options, long_options)
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(0)

    for currentArgument, currentValue in arguments:
        if currentArgument in ("-h", "--help"):
            usage()
        elif currentArgument in ("-t", "--target"):
            target = currentValue
        elif currentArgument in ("-T", "--tunnelTo"):
            tunnel_endpoint = currentValue
        elif currentArgument in ("-p", "--port"):
            LOCAL_PORT = int(currentValue)
        elif currentArgument in ("-b", "--bind"):
            bind = currentValue
        elif currentArgument in ("-e", "--encrypt"):
            ENCRYPTED_TUNNEL = True
            SECRET_KEY = currentValue.encode()
        elif currentArgument in ("-w", "--workers"):
            WORKERS = int(currentValue)
        elif currentArgument in ("-F", "--frag-size"):
            fs = int(currentValue)
            if fs < 1 or fs > 65535:
                print("Error: --frag-size must be between 1 and 65535")
                sys.exit(1)
            FRAGMENT_SIZE = fs
            FRAGMENT_SIZE_EXPLICIT = True
            print("Fragment size set to %d bytes (probe skipped)" % FRAGMENT_SIZE)
        elif currentArgument in ("-f", "--fast-close"):
            FAST_CLOSE = True
            print("Fast-close mode: SO_LINGER timeout=0 on burnout sockets")
        elif currentArgument in ("-v", "--verbose"):
            print("Verbose mode")
            VERBOSE = True
        else:
            assert False, "Unhandled Option"

    try:
        if len(target) > 0:
            target_list = target.split(":")
            TARGET_IP = target_list[0] if target_list[0] else "127.0.0.1"
            TARGET_PORT = int(target_list[1])
        if len(tunnel_endpoint) > 0:
            tunnel_endpoint_list = tunnel_endpoint.split(":")
            TUNNEL_SERVER_IP = tunnel_endpoint_list[0] if tunnel_endpoint_list[0] else "127.0.0.1"
            TUNNEL_SERVER_PORT = int(tunnel_endpoint_list[1])
        if len(bind) > 0:
            bind_list = bind.split(":")
            BIND_IP = bind_list[0] if bind_list[0] else "0.0.0.0"
            TUNNEL_SERVER_PORT = int(bind_list[1])
            log("bind port is %d" % TUNNEL_SERVER_PORT)
    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit(0)
    except Exception as e:
        print("Exception: %s" % str(e))
        traceback.print_tb(e.__traceback__)
        sys.exit(0)

    # tunnel client side
    if LOCAL_PORT > 0 and len(tunnel_endpoint) > 0 and len(target) > 0:
        if (len(TUNNEL_SERVER_IP) > 0 and TUNNEL_SERVER_PORT > 0
                and len(TARGET_IP) > 0 and TARGET_PORT > 0):
            # Probe the firewall's max fragment size before accepting local-app
            # traffic, unless -F was set explicitly.
            if not FRAGMENT_SIZE_EXPLICIT:
                if not probe_fragment_size():
                    sys.exit(1)
            local_server()

    # tunnel server side
    if len(BIND_IP) > 0 and TUNNEL_SERVER_PORT > 0:
        try:
            print("Binding fragmented server on %s:%d" % (BIND_IP, TUNNEL_SERVER_PORT))
            tunnel_server()
        except KeyboardInterrupt:
            print("Exiting...")
            sys.exit(0)

    try:
        while threading.active_count() > 1:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("Exiting...")
