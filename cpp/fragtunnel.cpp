// fragtunnel — C++ port for Linux (Debian-based).
// Wire-compatible with the Python implementation in ../fragtunnel.py.
//
// Build:   make
// Usage:   ./fragtunnel -b 0.0.0.0:9999                              (tunnel server)
//          ./fragtunnel -p 8080 -t HOST:PORT -T HOST:9999 [-w 8]      (tunnel client)

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// =================== Config ===================
constexpr size_t BUFFER_SIZE = 8192;
constexpr size_t HEADER_SIZE = 8;
constexpr size_t DEFAULT_FRAGMENT_SIZE = 1024;
constexpr int TARGET_FLUSH_IDLE_MS = 50;
constexpr int LONG_POLL_MS = 1000;
constexpr int LISTEN_BACKLOG = 1024;
constexpr int TARGET_RECV_TIMEOUT_US = 20000;

// =================== Globals (set at startup) ===================
int g_workers = 8;
size_t g_fragment_size = DEFAULT_FRAGMENT_SIZE;
bool g_fragment_size_explicit = false;  // user passed -F → skip the startup probe
std::string g_secret_key;
bool g_encrypted = false;
bool g_verbose = false;
bool g_fast_close = false;  // SO_LINGER timeout=0 on burnout sockets (RST close, no TIME_WAIT)

std::string g_tunnel_server_ip;
uint16_t g_tunnel_server_port = 0;
std::string g_target_ip;
uint16_t g_target_port = 0;
uint16_t g_local_port = 0;
std::string g_bind_ip;

// =================== Wire opcodes ===================
constexpr uint8_t OP_FRAG = 0x01;
constexpr uint8_t OP_EOD = 0x02;
constexpr uint8_t OP_ACK = 0x03;
constexpr uint8_t OP_ERR = 0x04;
constexpr uint8_t OP_TARGET = 0x05;
constexpr uint8_t OP_POLL = 0x06;
constexpr uint8_t OP_WAIT = 0x07;
constexpr uint8_t OP_DONE = 0x08;
constexpr uint8_t OP_PROBE = 0x09;          // client→server: payload of varying size; server ACKs
constexpr uint8_t OP_SET_FRAG_SIZE = 0x0A;  // client→server: seq = chosen fragment size; server ACKs

static std::mutex g_log_mtx;
static void log_msg(const std::string& msg) {
    if (!g_verbose) return;
    std::lock_guard<std::mutex> lk(g_log_mtx);
    std::cerr << msg << "\n";
}

// =================== XOR ===================
static void xor_buffer(uint8_t* data, size_t len, size_t key_offset) {
    if (g_secret_key.empty()) return;
    const size_t klen = g_secret_key.size();
    for (size_t i = 0; i < len; i++) {
        data[i] ^= (uint8_t)g_secret_key[(i + key_offset) % klen];
    }
}

// =================== Low-level I/O ===================
static bool recv_exact(int sock, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = recv(sock, buf + total, n - total, 0);
        if (r <= 0) return false;
        total += (size_t)r;
    }
    return true;
}

static bool send_all(int sock, const uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t s = send(sock, buf + total, n - total, MSG_NOSIGNAL);
        if (s <= 0) return false;
        total += (size_t)s;
    }
    return true;
}

static void set_nodelay(int sock) {
    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

// Burnout sockets: short-lived TCP carrying one frame. When --fast-close is
// set, also enable SO_LINGER timeout=0 so close() sends RST instead of FIN.
// That skips the TIME_WAIT state entirely, which is the dominant throughput
// ceiling for the burnout-socket pattern on Linux. NOT safe for persistent
// sockets (user connection / target connection) — RST can truncate unread data.
static void set_burnout_opts(int sock) {
    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (g_fast_close) {
        struct linger lg;
        lg.l_onoff = 1;
        lg.l_linger = 0;
        setsockopt(sock, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    }
}

static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// =================== Frame ===================
struct Frame {
    uint8_t opcode = 0;
    uint32_t seq = 0;
    std::vector<uint8_t> payload;

    std::vector<uint8_t> pack() const {
        std::vector<uint8_t> buf(HEADER_SIZE + payload.size());
        buf[0] = opcode;
        buf[1] = 0;
        uint16_t len_be = htons((uint16_t)payload.size());
        std::memcpy(buf.data() + 2, &len_be, 2);
        uint32_t seq_be = htonl(seq);
        std::memcpy(buf.data() + 4, &seq_be, 4);
        if (!payload.empty()) {
            std::memcpy(buf.data() + HEADER_SIZE, payload.data(), payload.size());
        }
        if (g_encrypted) xor_buffer(buf.data(), buf.size(), 0);
        return buf;
    }

    static bool recv_from(int sock, Frame& f) {
        uint8_t header[HEADER_SIZE];
        if (!recv_exact(sock, header, HEADER_SIZE)) return false;
        if (g_encrypted) xor_buffer(header, HEADER_SIZE, 0);
        f.opcode = header[0];
        uint16_t len_be;
        std::memcpy(&len_be, header + 2, 2);
        uint16_t len = ntohs(len_be);
        uint32_t seq_be;
        std::memcpy(&seq_be, header + 4, 4);
        f.seq = ntohl(seq_be);
        f.payload.resize(len);
        if (len > 0) {
            if (!recv_exact(sock, f.payload.data(), len)) return false;
            if (g_encrypted) xor_buffer(f.payload.data(), len, HEADER_SIZE);
        }
        return true;
    }
};

static bool send_frame(int sock, const Frame& f) {
    auto buf = f.pack();
    return send_all(sock, buf.data(), buf.size());
}

// =================== Burnout socket ===================
static int open_tunnel_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    set_burnout_opts(sock);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_tunnel_server_port);
    if (inet_pton(AF_INET, g_tunnel_server_ip.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

// One fresh TCP session: send one Frame, receive one Frame, close. Returns
// true on success (response in `resp`).
static bool send_one_frame(const Frame& req, Frame& resp) {
    int sock = open_tunnel_socket();
    if (sock < 0) return false;
    bool ok = send_frame(sock, req) && Frame::recv_from(sock, resp);
    close(sock);
    return ok;
}

// Like send_one_frame but with explicit send + recv timeouts. Used by the
// startup probe so that a firewall silently dropping the session manifests
// as a timeout rather than hanging forever.
static bool send_one_frame_timeout(const Frame& req, Frame& resp, int timeout_sec) {
    int sock = open_tunnel_socket();
    if (sock < 0) return false;
    timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    bool ok = send_frame(sock, req) && Frame::recv_from(sock, resp);
    close(sock);
    return ok;
}

// =================== TunnelSession ===================
struct TunnelSession {
    int workers;

    // Set once at handshake, then read-only.
    bool target_set = false;
    std::string target_ip;
    uint16_t target_port = 0;
    int target_sock = -1;

    std::atomic<bool> shutdown{false};

    // Inbound: assembled fragments from tunnel client, forwarded to target.
    std::mutex inbound_mtx;
    std::condition_variable inbound_cv;
    std::unordered_map<uint32_t, std::vector<uint8_t>> inbound;
    int inbound_total = -1;
    bool inbound_complete = false;

    // Outbound: fragments built from target replies, served via POLL.
    std::mutex outbound_mtx;
    std::condition_variable outbound_cv;
    std::vector<std::vector<uint8_t>> outbound;
    int outbound_total = -1;
    size_t outbound_next_seq = 0;
    int64_t outbound_last_append_ms = 0;

    explicit TunnelSession(int w) : workers(w) {}
};

// =================== Thread pool ===================
class ThreadPool {
public:
    explicit ThreadPool(size_t n) : stop_(false) {
        for (size_t i = 0; i < n; i++) {
            workers_.emplace_back([this] {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lk(mtx_);
                        cv_.wait(lk, [this] { return stop_ || !tasks_.empty(); });
                        if (stop_ && tasks_.empty()) return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    task();
                }
            });
        }
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lk(mtx_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& t : workers_) {
            if (t.joinable()) t.join();
        }
    }

    void enqueue(std::function<void()> task) {
        {
            std::unique_lock<std::mutex> lk(mtx_);
            tasks_.emplace(std::move(task));
        }
        cv_.notify_one();
    }

    template <class F>
    auto submit(F&& f) -> std::future<decltype(f())> {
        using R = decltype(f());
        auto pt = std::make_shared<std::packaged_task<R()>>(std::forward<F>(f));
        auto fut = pt->get_future();
        enqueue([pt]() { (*pt)(); });
        return fut;
    }

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mtx_;
    std::condition_variable cv_;
    bool stop_;
};

// =================== Tunnel client side ===================

// Send `data` as parallel FRAG frames + final EOD. Blocks until all are ACKed.
static bool send_fragments_parallel(const std::vector<uint8_t>& data, ThreadPool& pool) {
    if (data.empty()) return true;
    size_t total = (data.size() + g_fragment_size - 1) / g_fragment_size;

    std::vector<std::future<bool>> futs;
    futs.reserve(total);
    for (size_t i = 0; i < total; i++) {
        size_t start = i * g_fragment_size;
        size_t end = std::min(start + g_fragment_size, data.size());
        std::vector<uint8_t> frag(data.begin() + start, data.begin() + end);
        uint32_t seq = (uint32_t)i;
        futs.push_back(pool.submit([frag = std::move(frag), seq]() mutable -> bool {
            Frame req;
            req.opcode = OP_FRAG;
            req.seq = seq;
            req.payload = std::move(frag);
            Frame resp;
            if (!send_one_frame(req, resp)) return false;
            return resp.opcode == OP_ACK;
        }));
    }

    bool ok = true;
    for (auto& f : futs) {
        if (!f.get()) ok = false;
    }
    if (!ok) return false;

    Frame eod;
    eod.opcode = OP_EOD;
    eod.seq = (uint32_t)total;
    Frame resp;
    if (!send_one_frame(eod, resp)) return false;
    return resp.opcode == OP_ACK;
}

// Maintain `workers` outstanding POLLs; reassemble FRAGs by seq and deliver
// each completed batch eagerly to the local app (don't wait for trailing
// long-pollers).
static void poll_loop(TunnelSession& session, int local_sock, ThreadPool& pool) {
    std::unordered_map<uint32_t, std::vector<uint8_t>> inbound;
    int inbound_total = -1;

    while (!session.shutdown.load()) {
        struct ResultQueue {
            std::mutex mtx;
            std::condition_variable cv;
            std::queue<Frame> q;
        };
        ResultQueue rq;
        std::atomic<int> remaining{session.workers};

        for (int i = 0; i < session.workers; i++) {
            pool.enqueue([&rq, &remaining]() {
                Frame req;
                req.opcode = OP_POLL;
                Frame resp;
                bool ok = send_one_frame(req, resp);
                {
                    std::lock_guard<std::mutex> lk(rq.mtx);
                    if (ok) rq.q.push(std::move(resp));
                    else rq.q.push(Frame{});
                }
                remaining.fetch_sub(1);
                rq.cv.notify_one();
            });
        }

        int processed = 0;
        while (processed < session.workers) {
            Frame resp;
            {
                std::unique_lock<std::mutex> lk(rq.mtx);
                rq.cv.wait(lk, [&]() { return !rq.q.empty(); });
                resp = std::move(rq.q.front());
                rq.q.pop();
            }
            processed++;

            if (resp.opcode == OP_FRAG) {
                inbound[resp.seq] = std::move(resp.payload);
            } else if (resp.opcode == OP_DONE) {
                inbound_total = (int)resp.seq;
            } else if (resp.opcode == OP_ERR) {
                log_msg("POLL got ERR");
                session.shutdown.store(true);
                return;
            }

            // Eager delivery
            if (inbound_total >= 0 && (int)inbound.size() >= inbound_total) {
                std::vector<uint8_t> joined;
                bool hole = false;
                for (int i = 0; i < inbound_total; i++) {
                    auto it = inbound.find((uint32_t)i);
                    if (it == inbound.end()) { hole = true; break; }
                    joined.insert(joined.end(), it->second.begin(), it->second.end());
                }
                if (hole) {
                    log_msg("Reassembly hole; aborting batch");
                    inbound.clear();
                    inbound_total = -1;
                    continue;
                }
                if (!send_all(local_sock, joined.data(), joined.size())) {
                    session.shutdown.store(true);
                    return;
                }
                inbound.clear();
                inbound_total = -1;
            }
        }
    }
}

static void handle_local_client(int local_sock, TunnelSession& session) {
    ThreadPool send_pool(session.workers);
    ThreadPool poll_pool(session.workers);

    std::thread poll_thr([&]() { poll_loop(session, local_sock, poll_pool); });

    std::vector<uint8_t> buf(BUFFER_SIZE);
    while (!session.shutdown.load()) {
        ssize_t r = recv(local_sock, buf.data(), buf.size(), 0);
        if (r <= 0) break;
        std::vector<uint8_t> chunk(buf.data(), buf.data() + r);
        if (!send_fragments_parallel(chunk, send_pool)) {
            log_msg("Outbound batch failed");
            break;
        }
    }

    session.shutdown.store(true);
    if (poll_thr.joinable()) poll_thr.join();
}

static void local_server() {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_local_port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return;
    }
    listen(srv, LISTEN_BACKLOG);
    std::cout << "Local server listening on port " << g_local_port << "\n";

    while (true) {
        sockaddr_in cli{};
        socklen_t clen = sizeof(cli);
        int csock = accept(srv, (sockaddr*)&cli, &clen);
        if (csock < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        set_nodelay(csock);

        TunnelSession session(g_workers);
        session.target_ip = g_target_ip;
        session.target_port = g_target_port;

        std::string ts = g_target_ip + ":" + std::to_string(g_target_port);
        Frame req;
        req.opcode = OP_TARGET;
        req.payload.assign(ts.begin(), ts.end());
        Frame resp;
        if (!send_one_frame(req, resp) || resp.opcode != OP_ACK) {
            std::cerr << "Target handshake failed (mismatched encryption?)\n";
            close(csock);
            continue;
        }
        session.target_set = true;
        log_msg("Target handshake OK");

        handle_local_client(csock, session);
        close(csock);
    }
    close(srv);
}

// =================== Tunnel server side ===================

static int open_target_socket(TunnelSession& session) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    set_nodelay(sock);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(session.target_port);
    if (inet_pton(AF_INET, session.target_ip.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

// Reads from target_sock, chunks into g_fragment_size-byte pieces, signals POLL
// waiters. Idle-flushes the current batch after TARGET_FLUSH_IDLE_MS of silence.
static void target_reader_thread(TunnelSession* session) {
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = TARGET_RECV_TIMEOUT_US;
    setsockopt(session->target_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    std::vector<uint8_t> buf(BUFFER_SIZE);
    while (!session->shutdown.load()) {
        ssize_t r = recv(session->target_sock, buf.data(), buf.size(), 0);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::unique_lock<std::mutex> lk(session->outbound_mtx);
                bool has = !session->outbound.empty();
                bool fresh = (now_ms() - session->outbound_last_append_ms) >= TARGET_FLUSH_IDLE_MS;
                if (has && fresh && session->outbound_total < 0) {
                    session->outbound_total = (int)session->outbound.size();
                    session->outbound_cv.notify_all();
                }
                continue;
            }
            log_msg("target recv error");
            break;
        }
        if (r == 0) {
            std::unique_lock<std::mutex> lk(session->outbound_mtx);
            if (session->outbound_total < 0) {
                session->outbound_total = (int)session->outbound.size();
            }
            session->outbound_cv.notify_all();
            break;
        }
        // Append fragments
        size_t total = ((size_t)r + g_fragment_size - 1) / g_fragment_size;
        std::vector<std::vector<uint8_t>> frags;
        frags.reserve(total);
        for (size_t i = 0; i < total; i++) {
            size_t s = i * g_fragment_size;
            size_t e = std::min(s + g_fragment_size, (size_t)r);
            frags.emplace_back(buf.data() + s, buf.data() + e);
        }
        {
            std::unique_lock<std::mutex> lk(session->outbound_mtx);
            if (session->outbound_total >= 0 &&
                (int)session->outbound_next_seq >= session->outbound_total) {
                session->outbound.clear();
                session->outbound_total = -1;
                session->outbound_next_seq = 0;
            }
            for (auto& f : frags) session->outbound.push_back(std::move(f));
            session->outbound_last_append_ms = now_ms();
            session->outbound_cv.notify_all();
        }
    }
    {
        std::unique_lock<std::mutex> lk(session->outbound_mtx);
        session->outbound_cv.notify_all();
    }
    session->shutdown.store(true);
}

// Waits on inbound_complete, joins fragments in seq order, forwards to target.
static void inbound_reassembler_thread(TunnelSession* session) {
    while (!session->shutdown.load()) {
        std::vector<uint8_t> joined;
        {
            std::unique_lock<std::mutex> lk(session->inbound_mtx);
            session->inbound_cv.wait_for(lk, std::chrono::milliseconds(500), [&]() {
                return session->inbound_complete || session->shutdown.load();
            });
            if (session->shutdown.load()) return;
            if (!session->inbound_complete) continue;
            int total = session->inbound_total;
            if (total < 0 || (int)session->inbound.size() < (size_t)total) {
                session->inbound_complete = false;
                continue;
            }
            joined.reserve((size_t)total * g_fragment_size);
            bool hole = false;
            for (int i = 0; i < total; i++) {
                auto it = session->inbound.find((uint32_t)i);
                if (it == session->inbound.end()) { hole = true; break; }
                joined.insert(joined.end(), it->second.begin(), it->second.end());
            }
            session->inbound.clear();
            session->inbound_total = -1;
            session->inbound_complete = false;
            if (hole) {
                log_msg("inbound reassembly hole");
                continue;
            }
        }
        if (!joined.empty()) {
            if (!send_all(session->target_sock, joined.data(), joined.size())) {
                session->shutdown.store(true);
                return;
            }
        }
    }
}

// Long-polling POLL handler.
static void handle_poll(int conn, TunnelSession& session) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(LONG_POLL_MS);
    Frame resp;
    {
        std::unique_lock<std::mutex> lk(session.outbound_mtx);
        for (;;) {
            if (session.shutdown.load()) {
                resp.opcode = OP_WAIT;
                break;
            }
            size_t next = session.outbound_next_seq;
            int total = session.outbound_total;
            size_t olen = session.outbound.size();

            if (next < olen) {
                resp.opcode = OP_FRAG;
                resp.seq = (uint32_t)next;
                resp.payload = std::move(session.outbound[next]);
                session.outbound_next_seq++;
                break;
            }
            if (total >= 0 && (int)next >= total) {
                resp.opcode = OP_DONE;
                resp.seq = (uint32_t)total;
                session.outbound.clear();
                session.outbound_total = -1;
                session.outbound_next_seq = 0;
                break;
            }
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                resp.opcode = OP_WAIT;
                break;
            }
            session.outbound_cv.wait_until(lk, deadline);
        }
    }
    send_frame(conn, resp);
}

// One-time handshake: parse "ip:port", connect to target, spawn reader and
// reassembler threads.
static void handle_target_frame(int conn, const Frame& f, TunnelSession& session) {
    std::string addr(f.payload.begin(), f.payload.end());
    auto colon = addr.find(':');
    if (colon == std::string::npos) {
        std::cerr << "Malformed TARGET frame (mismatched encryption?)\n";
        Frame err; err.opcode = OP_ERR;
        send_frame(conn, err);
        return;
    }
    if (session.target_set) {
        Frame ack; ack.opcode = OP_ACK;
        send_frame(conn, ack);
        return;
    }
    session.target_ip = addr.substr(0, colon);
    session.target_port = (uint16_t)std::atoi(addr.substr(colon + 1).c_str());
    session.target_sock = open_target_socket(session);
    if (session.target_sock < 0) {
        std::cerr << "Could not connect to target " << session.target_ip
                  << ":" << session.target_port << "\n";
        Frame err; err.opcode = OP_ERR;
        send_frame(conn, err);
        return;
    }
    session.target_set = true;
    log_msg("Target set to " + session.target_ip + ":" + std::to_string(session.target_port));
    std::thread(target_reader_thread, &session).detach();
    std::thread(inbound_reassembler_thread, &session).detach();
    Frame ack; ack.opcode = OP_ACK;
    send_frame(conn, ack);
}

// One-shot frame handler. Runs in the server's bounded thread pool, one task
// per accepted TCP. Reads exactly one frame, dispatches, sends one response.
static void handle_tunnel_session_frame(int conn, TunnelSession& session) {
    Frame f;
    if (!Frame::recv_from(conn, f)) {
        close(conn);
        return;
    }

    if (f.opcode == OP_TARGET) {
        handle_target_frame(conn, f, session);
        close(conn);
        return;
    }
    // PROBE and SET_FRAG_SIZE happen at client startup, before any TARGET
    // handshake. They must work regardless of session.target_set.
    if (f.opcode == OP_PROBE) {
        Frame ack; ack.opcode = OP_ACK;
        send_frame(conn, ack);
        close(conn);
        return;
    }
    if (f.opcode == OP_SET_FRAG_SIZE) {
        if (f.seq >= 1 && f.seq <= 65535) {
            g_fragment_size = (size_t)f.seq;
            log_msg("Server fragment size set to " + std::to_string(g_fragment_size));
        }
        Frame ack; ack.opcode = OP_ACK;
        send_frame(conn, ack);
        close(conn);
        return;
    }
    if (!session.target_set) {
        Frame err; err.opcode = OP_ERR;
        send_frame(conn, err);
        close(conn);
        return;
    }

    if (f.opcode == OP_FRAG) {
        {
            std::unique_lock<std::mutex> lk(session.inbound_mtx);
            session.inbound[f.seq] = std::move(f.payload);
            if (session.inbound_total >= 0 &&
                (int)session.inbound.size() >= (size_t)session.inbound_total) {
                session.inbound_complete = true;
                session.inbound_cv.notify_one();
            }
        }
        Frame ack; ack.opcode = OP_ACK;
        send_frame(conn, ack);
    } else if (f.opcode == OP_EOD) {
        {
            std::unique_lock<std::mutex> lk(session.inbound_mtx);
            session.inbound_total = (int)f.seq;
            if ((int)session.inbound.size() >= session.inbound_total) {
                session.inbound_complete = true;
                session.inbound_cv.notify_one();
            }
        }
        Frame ack; ack.opcode = OP_ACK;
        send_frame(conn, ack);
    } else if (f.opcode == OP_POLL) {
        handle_poll(conn, session);
    } else {
        Frame err; err.opcode = OP_ERR;
        send_frame(conn, err);
    }
    close(conn);
}

static void tunnel_server() {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_tunnel_server_port);
    inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr);
    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return;
    }
    listen(srv, LISTEN_BACKLOG);

    size_t pool_size = std::max((size_t)(g_workers * 4), (size_t)64);
    ThreadPool pool(pool_size);
    std::cout << "Tunnel server listening on port " << g_tunnel_server_port
              << " (pool=" << pool_size << ", backlog=" << LISTEN_BACKLOG << ")\n";

    auto session = std::make_shared<TunnelSession>(g_workers);

    while (true) {
        sockaddr_in cli{};
        socklen_t clen = sizeof(cli);
        int conn = accept(srv, (sockaddr*)&cli, &clen);
        if (conn < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        set_burnout_opts(conn);
        TunnelSession* sp = session.get();
        pool.enqueue([conn, sp]() { handle_tunnel_session_frame(conn, *sp); });
    }
    close(srv);
}

// =================== Startup fragment-size probe ===================

// Walk fragment sizes upward in 1024-byte steps until the tunnel server stops
// responding (firewall has cut us off) or we hit the 16 KB cap. Sets
// g_fragment_size to the largest size that successfully round-tripped, and
// tells the tunnel server to use the same size for its outbound chunking via
// OP_SET_FRAG_SIZE. Runs once at tunnel-client startup, before local_server().
//
// Returns false on fatal failure (cannot reach tunnel server at all). The
// caller should treat that as a hard error.
static constexpr size_t PROBE_STEP = 1024;
static constexpr size_t PROBE_MAX = 16384;
static constexpr int PROBE_TIMEOUT_SEC = 3;

static bool probe_fragment_size() {
    std::cerr << "Probing maximum fragment size (1024..16384, step 1024)...\n";
    size_t max_ok = 0;

    for (size_t size = PROBE_STEP; size <= PROBE_MAX; size += PROBE_STEP) {
        Frame req;
        req.opcode = OP_PROBE;
        req.payload.resize(size);
        // Pseudo-random fill so the payload doesn't look constant on the wire.
        for (size_t i = 0; i < size; i++) {
            req.payload[i] = (uint8_t)(std::rand() & 0xff);
        }

        Frame resp;
        bool ok = send_one_frame_timeout(req, resp, PROBE_TIMEOUT_SEC);
        if (ok && resp.opcode == OP_ACK) {
            std::cerr << "  " << size << " bytes: OK\n";
            max_ok = size;
        } else {
            std::cerr << "  " << size << " bytes: FAILED (firewall cap or server unreachable)\n";
            break;
        }
    }

    if (max_ok == 0) {
        std::cerr << "Probe failed at " << PROBE_STEP << " bytes — even the minimum\n"
                  << "fragment size doesn't round-trip. Is the tunnel server up?\n"
                  << "Is the firewall blocking all traffic? Check -e/--encrypt matches.\n";
        return false;
    }

    std::cerr << "Probed max fragment size: " << max_ok << " bytes\n";
    g_fragment_size = max_ok;

    // Tell the server to use this size for its outbound (target → local-app) chunking.
    Frame req;
    req.opcode = OP_SET_FRAG_SIZE;
    req.seq = (uint32_t)max_ok;
    Frame resp;
    if (send_one_frame_timeout(req, resp, PROBE_TIMEOUT_SEC) && resp.opcode == OP_ACK) {
        std::cerr << "Server acknowledged fragment size " << max_ok << "\n";
    } else {
        std::cerr << "Warning: server did not ACK SET_FRAG_SIZE; its outbound\n"
                  << "         responses may still use the default fragment size.\n";
    }
    return true;
}

// =================== CLI ===================
static void usage(const char* argv0) {
    std::cerr << "\nUsage: " << argv0
              << " -p port -t target_ip:port -T tunnel_ip:port -b bind_ip:port -e secret -w workers\n\n"
              << "-h --help        help\n"
              << "-p --port        local port to listen for the app\n"
              << "-t --target      target ip:port\n"
              << "-T --tunnelTo    tunnel server ip:port\n"
              << "-b --bind        tunnel server listen ip:port\n"
              << "-e --encrypt     XOR encrypt with provided secret\n"
              << "-w --workers     parallel fragment workers (default 8)\n"
              << "-F --frag-size   bytes per fragment (max 65535). If omitted, tunnel\n"
              << "                 client probes the firewall at startup (1024..16384,\n"
              << "                 step 1024) and uses the largest size that round-trips.\n"
              << "                 Explicit -F skips the probe.\n"
              << "-f --fast-close  SO_LINGER timeout=0 on burnout sockets (RST close,\n"
              << "                 skips TIME_WAIT — large throughput win on Linux)\n"
              << "-v --verbose     verbose mode\n";
    std::exit(0);
}

static bool parse_ip_port(const std::string& s, std::string& ip, uint16_t& port,
                          const std::string& default_ip) {
    auto colon = s.find(':');
    if (colon == std::string::npos) return false;
    std::string host = s.substr(0, colon);
    ip = host.empty() ? default_ip : host;
    int p = std::atoi(s.substr(colon + 1).c_str());
    if (p <= 0 || p > 65535) return false;
    port = (uint16_t)p;
    return true;
}

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);

    if (argc < 2) usage(argv[0]);

    std::string target_arg, tunnel_arg, bind_arg;

    static struct option long_opts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"target", required_argument, nullptr, 't'},
        {"tunnelTo", required_argument, nullptr, 'T'},
        {"port", required_argument, nullptr, 'p'},
        {"bind", required_argument, nullptr, 'b'},
        {"encrypt", required_argument, nullptr, 'e'},
        {"workers", required_argument, nullptr, 'w'},
        {"frag-size", required_argument, nullptr, 'F'},
        {"fast-close", no_argument, nullptr, 'f'},
        {"verbose", no_argument, nullptr, 'v'},
        {nullptr, 0, nullptr, 0}};

    int c;
    while ((c = getopt_long(argc, argv, "ht:T:p:b:e:w:F:fv", long_opts, nullptr)) != -1) {
        switch (c) {
            case 'h': usage(argv[0]); break;
            case 't': target_arg = optarg; break;
            case 'T': tunnel_arg = optarg; break;
            case 'p': g_local_port = (uint16_t)std::atoi(optarg); break;
            case 'b': bind_arg = optarg; break;
            case 'e': g_secret_key = optarg; g_encrypted = true; break;
            case 'w': g_workers = std::atoi(optarg); break;
            case 'F': {
                int fs = std::atoi(optarg);
                if (fs < 1 || fs > 65535) {
                    std::cerr << "Error: --frag-size must be between 1 and 65535\n";
                    return 1;
                }
                g_fragment_size = (size_t)fs;
                g_fragment_size_explicit = true;
                std::cerr << "Fragment size set to " << g_fragment_size << " bytes (probe skipped)\n";
                break;
            }
            case 'f': g_fast_close = true; break;
            case 'v': g_verbose = true; std::cerr << "Verbose mode\n"; break;
            default: usage(argv[0]);
        }
    }

    if (g_fast_close) {
        std::cerr << "Fast-close mode: SO_LINGER timeout=0 on burnout sockets\n";
    }

    if (!target_arg.empty() &&
        !parse_ip_port(target_arg, g_target_ip, g_target_port, "127.0.0.1")) {
        std::cerr << "Invalid -t format (expected ip:port)\n";
        return 1;
    }
    if (!tunnel_arg.empty() &&
        !parse_ip_port(tunnel_arg, g_tunnel_server_ip, g_tunnel_server_port, "127.0.0.1")) {
        std::cerr << "Invalid -T format\n";
        return 1;
    }
    if (!bind_arg.empty()) {
        std::string ip;
        uint16_t port;
        if (!parse_ip_port(bind_arg, ip, port, "0.0.0.0")) {
            std::cerr << "Invalid -b format\n";
            return 1;
        }
        g_bind_ip = ip;
        g_tunnel_server_port = port;
    }

    if (g_workers <= 0) g_workers = 1;

    if (g_local_port > 0 && !tunnel_arg.empty() && !target_arg.empty()) {
        // Tunnel client mode. Probe the firewall's maximum fragment size before
        // accepting any local-app traffic — unless the user already pinned the
        // size with -F.
        if (!g_fragment_size_explicit) {
            std::srand((unsigned)std::time(nullptr));
            if (!probe_fragment_size()) {
                return 1;
            }
        }
        local_server();
    } else if (!g_bind_ip.empty() && g_tunnel_server_port > 0) {
        std::cout << "Binding fragmented server on " << g_bind_ip << ":"
                  << g_tunnel_server_port << "\n";
        tunnel_server();
    } else {
        usage(argv[0]);
    }
    return 0;
}
