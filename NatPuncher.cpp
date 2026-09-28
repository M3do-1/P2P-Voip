// ============================================================================
//  NatPuncher  -  P2P VOIP + CHAT + FILE
//
//  Serverless peer-to-peer voice chat, text messaging and file transfer over
//  UDP, using manual NAT hole punching and AES-256-GCM authenticated
//  encryption with a pre-shared key (key.txt).
//
//  Reconstructed from the original binary. Faithful to the observed behaviour
//  (same libraries, same protocol shape, same console output) but not a
//  byte-for-byte recovery of the lost source.
//
//  Dependencies:
//    - Winsock2   (ws2_32)                 UDP sockets
//    - Opus       (opus.dll / opus.lib)    voice codec, 48 kHz mono float
//    - OpenSSL    (libcrypto-3-x64.dll)    AES-256-GCM
//    - miniaudio  (miniaudio.h, header)    mic capture + speaker playback
//
//  Build: see README.md / CMakeLists.txt
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <fstream>
#include <iostream>

#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio.h"

#include <opus.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#pragma comment(lib, "ws2_32.lib")

// ----------------------------------------------------------------------------
//  Constants
// ----------------------------------------------------------------------------
static const int   SAMPLE_RATE   = 48000;
static const int   CHANNELS      = 1;
static const int   FRAME_SAMPLES = 960;      // 20 ms @ 48 kHz
static const int   KEY_LEN       = 32;       // AES-256
static const int   IV_LEN        = 12;       // GCM nonce
static const int   TAG_LEN       = 16;       // GCM tag
static const int   FILE_CHUNK    = 1024;     // payload bytes per file packet
static const long  SPEEDTEST_BYTES = 100L * 1024 * 1024; // 100 MB

// Packet types (first plaintext byte, so the type is authenticated by GCM)
enum PktType : uint8_t {
    PKT_HELLO      = 0,
    PKT_HELLO_ACK  = 1,
    PKT_VOICE      = 2,
    PKT_TEXT       = 3,
    PKT_FILE_META  = 4,
    PKT_FILE_CHUNK = 5,
    PKT_FILE_END   = 6,
    PKT_FILE_ACK   = 7,
    PKT_SPEED_BEG  = 8,
    PKT_SPEED_DAT  = 9,
    PKT_SPEED_END  = 10,
};

// ----------------------------------------------------------------------------
//  Global state
// ----------------------------------------------------------------------------
static SOCKET             g_sock = INVALID_SOCKET;
static sockaddr_in        g_peer{};
static uint8_t            g_key[KEY_LEN];
static std::atomic<bool>  g_running{ true };
static std::atomic<bool>  g_verified{ false };
static std::mutex         g_sendMtx;

static OpusEncoder*       g_enc = nullptr;
static OpusDecoder*       g_dec = nullptr;

// File-receive state
static std::ofstream      g_recvFile;
static uint64_t           g_recvExpected = 0;   // total size announced
static uint64_t           g_recvGot      = 0;
static uint32_t           g_recvSeq      = 0;    // next expected chunk index

// File-send ACK signalling
static std::atomic<int64_t> g_lastAck{ -1 };

// Speed-test receive state
static std::atomic<bool>  g_speedActive{ false };
static uint64_t           g_speedBytes  = 0;
static std::chrono::steady_clock::time_point g_speedStart;

// ----------------------------------------------------------------------------
//  Thread-safe float ring buffer (for audio capture / playback)
// ----------------------------------------------------------------------------
struct FloatRing {
    std::mutex        m;
    std::deque<float> q;
    size_t            cap = SAMPLE_RATE; // ~1 s cushion

    void push(const float* d, size_t n) {
        std::lock_guard<std::mutex> lk(m);
        for (size_t i = 0; i < n; ++i) {
            if (q.size() >= cap) q.pop_front(); // drop oldest on overflow
            q.push_back(d[i]);
        }
    }
    size_t pop(float* d, size_t n) {
        std::lock_guard<std::mutex> lk(m);
        size_t k = 0;
        while (k < n && !q.empty()) { d[k++] = q.front(); q.pop_front(); }
        return k;
    }
    size_t size() {
        std::lock_guard<std::mutex> lk(m);
        return q.size();
    }
};
static FloatRing g_capRing;   // mic  -> encoder
static FloatRing g_playRing;  // decoder -> speaker

// ----------------------------------------------------------------------------
//  AES-256-GCM helpers  (layout on the wire: [IV(12)] [ciphertext] [TAG(16)])
// ----------------------------------------------------------------------------
static bool gcm_encrypt(const uint8_t* pt, int ptLen, std::vector<uint8_t>& out) {
    uint8_t iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    int len = 0, total = 0;
    out.resize(IV_LEN + ptLen + TAG_LEN);
    memcpy(out.data(), iv, IV_LEN);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, g_key, iv) == 1 &&
        EVP_EncryptUpdate(ctx, out.data() + IV_LEN, &len, pt, ptLen) == 1) {
        total = len;
        if (EVP_EncryptFinal_ex(ctx, out.data() + IV_LEN + total, &len) == 1) {
            total += len;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN,
                                    out.data() + IV_LEN + total) == 1) {
                out.resize(IV_LEN + total + TAG_LEN);
                ok = true;
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static bool gcm_decrypt(const uint8_t* in, int inLen, std::vector<uint8_t>& out) {
    if (inLen < IV_LEN + TAG_LEN) return false;
    const uint8_t* iv  = in;
    const uint8_t* ct  = in + IV_LEN;
    int            ctLen = inLen - IV_LEN - TAG_LEN;
    const uint8_t* tag = in + IV_LEN + ctLen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    int len = 0, total = 0;
    out.resize(ctLen > 0 ? ctLen : 1);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, g_key, iv) == 1 &&
        EVP_DecryptUpdate(ctx, out.data(), &len, ct, ctLen) == 1) {
        total = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                                (void*)tag) == 1 &&
            EVP_DecryptFinal_ex(ctx, out.data() + total, &len) == 1) { // tag check
            total += len;
            out.resize(total);
            ok = true;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok; // false => wrong key / tampered => caller drops the packet
}

// ----------------------------------------------------------------------------
//  Send: prepend type byte, encrypt, sendto peer  (thread-safe)
// ----------------------------------------------------------------------------
static bool send_pkt(uint8_t type, const uint8_t* data, int len) {
    std::vector<uint8_t> pt(1 + len);
    pt[0] = type;
    if (len) memcpy(pt.data() + 1, data, len);

    std::vector<uint8_t> ct;
    if (!gcm_encrypt(pt.data(), (int)pt.size(), ct)) return false;

    std::lock_guard<std::mutex> lk(g_sendMtx);
    int n = sendto(g_sock, (const char*)ct.data(), (int)ct.size(), 0,
                   (sockaddr*)&g_peer, sizeof(g_peer));
    return n == (int)ct.size();
}
static bool send_pkt(uint8_t type, const std::string& s) {
    return send_pkt(type, (const uint8_t*)s.data(), (int)s.size());
}

// ----------------------------------------------------------------------------
//  Audio: miniaudio duplex callback
//    input  frames -> capture ring (encoded+sent by the sender thread)
//    output frames <- playback ring (filled by the receive thread's decoder)
// ----------------------------------------------------------------------------
static void audio_callback(ma_device*, void* pOutput, const void* pInput, ma_uint32 frames) {
    if (pInput)  g_capRing.push((const float*)pInput, frames);

    float* out = (float*)pOutput;
    size_t got = g_playRing.pop(out, frames);
    for (size_t i = got; i < frames; ++i) out[i] = 0.0f; // underflow -> silence
}

// Pull 20 ms frames from the capture ring, Opus-encode, encrypt, send.
static void audio_sender_thread() {
    std::vector<float>   frame(FRAME_SAMPLES);
    std::vector<uint8_t> enc(4000);
    while (g_running) {
        if (g_capRing.size() >= (size_t)FRAME_SAMPLES) {
            g_capRing.pop(frame.data(), FRAME_SAMPLES);
            int bytes = opus_encode_float(g_enc, frame.data(), FRAME_SAMPLES,
                                          enc.data(), (opus_int32)enc.size());
            if (bytes > 0) send_pkt(PKT_VOICE, enc.data(), bytes);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }
}

// ----------------------------------------------------------------------------
//  Receive thread: decrypt every datagram, dispatch by type
// ----------------------------------------------------------------------------
static void recv_thread() {
    std::vector<uint8_t> buf(65536);
    std::vector<float>   pcm(FRAME_SAMPLES * 6);

    while (g_running) {
        sockaddr_in from{}; int fromLen = sizeof(from);
        int n = recvfrom(g_sock, (char*)buf.data(), (int)buf.size(), 0,
                         (sockaddr*)&from, &fromLen);
        if (n <= 0) continue;

        std::vector<uint8_t> pt;
        if (!gcm_decrypt(buf.data(), n, pt) || pt.empty())
            continue;                       // wrong key / not our peer -> ignore

        uint8_t  type = pt[0];
        uint8_t* data = pt.data() + 1;
        int      dlen = (int)pt.size() - 1;

        switch (type) {
        case PKT_HELLO:
            send_pkt(PKT_HELLO_ACK, nullptr, 0);
            break;

        case PKT_HELLO_ACK:
            g_verified = true;
            break;

        case PKT_VOICE: {
            int samples = opus_decode_float(g_dec, data, dlen, pcm.data(),
                                            FRAME_SAMPLES * 6, 0);
            if (samples > 0) g_playRing.push(pcm.data(), samples);
            break;
        }

        case PKT_TEXT:
            std::cout << "\n[Peer]: " << std::string((char*)data, dlen)
                      << "\n> " << std::flush;
            break;

        case PKT_FILE_META: {
            // payload: "<filename>|<size>"
            std::string meta((char*)data, dlen);
            size_t bar = meta.find('|');
            std::string name = meta.substr(0, bar);
            g_recvExpected = strtoull(meta.substr(bar + 1).c_str(), nullptr, 10);
            g_recvGot = 0; g_recvSeq = 0;
            std::string outName = "recv_" + name;
            g_recvFile.open(outName, std::ios::binary | std::ios::trunc);
            std::cout << "\nDownloading: " << name << " ("
                      << g_recvExpected << " bytes)\n" << std::flush;
            break;
        }

        case PKT_FILE_CHUNK: {
            if (dlen < 4) break;
            uint32_t seq; memcpy(&seq, data, 4);
            if (seq == g_recvSeq && g_recvFile.is_open()) {
                g_recvFile.write((char*)data + 4, dlen - 4);
                g_recvGot += (dlen - 4);
                g_recvSeq++;
            }
            uint32_t ackSeq = seq;            // ACK the seq we just handled
            send_pkt(PKT_FILE_ACK, (uint8_t*)&ackSeq, 4);
            break;
        }

        case PKT_FILE_END:
            if (g_recvFile.is_open()) g_recvFile.close();
            std::cout << "\rFile Saved.                         \n> " << std::flush;
            break;

        case PKT_FILE_ACK: {
            if (dlen >= 4) { uint32_t s; memcpy(&s, data, 4); g_lastAck = (int64_t)s; }
            break;
        }

        case PKT_SPEED_BEG:
            g_speedActive = true;
            g_speedBytes  = 0;
            g_speedStart  = std::chrono::steady_clock::now();
            std::cout << "\nReceiving Speed Test (100 MB)...\n" << std::flush;
            break;

        case PKT_SPEED_DAT:
            if (g_speedActive) g_speedBytes += dlen;
            break;

        case PKT_SPEED_END: {
            double secs = std::chrono::duration<double>(
                              std::chrono::steady_clock::now() - g_speedStart).count();
            double mb   = g_speedBytes / (1024.0 * 1024.0);
            g_speedActive = false;
            std::cout << "Received 100MB in " << secs << "s. Speed: "
                      << (secs > 0 ? mb / secs : 0.0) << " MB/s\n> " << std::flush;
            break;
        }
        }
    }
}

// ----------------------------------------------------------------------------
//  Reliable-ish file upload (stop-and-wait per chunk over UDP)
// ----------------------------------------------------------------------------
static void upload_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { std::cout << "File not found!\n"; return; }

    uint64_t size = (uint64_t)f.tellg();
    f.seekg(0);

    std::string base = path;
    size_t slash = base.find_last_of("/\\");
    if (slash != std::string::npos) base = base.substr(slash + 1);

    std::cout << "Uploading: " << base << " (" << size << " bytes)\n";
    send_pkt(PKT_FILE_META, base + "|" + std::to_string(size));

    std::vector<uint8_t> pkt(4 + FILE_CHUNK);
    uint32_t seq = 0;
    uint64_t sent = 0;

    while (sent < size && g_running) {
        f.read((char*)pkt.data() + 4, FILE_CHUNK);
        int got = (int)f.gcount();
        memcpy(pkt.data(), &seq, 4);

        // send + wait for matching ACK, retransmit up to 10 times
        bool acked = false;
        for (int tries = 0; tries < 10 && !acked; ++tries) {
            send_pkt(PKT_FILE_CHUNK, pkt.data(), 4 + got);
            auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(400);
            while (std::chrono::steady_clock::now() < deadline) {
                if (g_lastAck.load() == (int64_t)seq) { acked = true; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        sent += got;
        seq++;
        int pct = size ? (int)(sent * 100 / size) : 100;
        std::cout << "\rUploading: " << pct << "%   " << std::flush;
    }
    send_pkt(PKT_FILE_END, nullptr, 0);
    std::cout << "\rUpload Complete.            \n";
}

// ----------------------------------------------------------------------------
//  Memory speed test: blast 100 MB of in-memory data to the peer
// ----------------------------------------------------------------------------
static void run_speedtest() {
    std::cout << "Starting Memory Speed Test (100 MB)...\n";
    send_pkt(PKT_SPEED_BEG, nullptr, 0);

    std::vector<uint8_t> chunk(1200, 0xAB);
    long sent = 0;
    while (sent < SPEEDTEST_BYTES && g_running) {
        send_pkt(PKT_SPEED_DAT, chunk.data(), (int)chunk.size());
        sent += (long)chunk.size();
        // light pacing so we don't overrun the local send buffer completely
        if ((sent % (1200 * 200)) == 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    send_pkt(PKT_SPEED_END, nullptr, 0);
    std::cout << "Speed test data sent.\n";
}

// ----------------------------------------------------------------------------
//  Load 32-byte key from a 64-char hex file (key.txt)
// ----------------------------------------------------------------------------
static bool load_key(const char* path) {
    std::ifstream f(path);
    if (!f) return false;
    std::string hex; f >> hex;
    if (hex.size() < KEY_LEN * 2) return false;
    for (int i = 0; i < KEY_LEN; ++i)
        g_key[i] = (uint8_t)strtoul(hex.substr(i * 2, 2).c_str(), nullptr, 16);
    return true;
}

// ----------------------------------------------------------------------------
//  Hole punch + verify: spam HELLO until the peer's HELLO_ACK comes back
// ----------------------------------------------------------------------------
static bool punch_and_verify(const std::string& ip, int port) {
    g_peer.sin_family = AF_INET;
    g_peer.sin_port   = htons((u_short)port);
    inet_pton(AF_INET, ip.c_str(), &g_peer.sin_addr);

    std::cout << "Trying to punch hole to " << ip << ":" << port << " ...\n";

    for (int i = 0; i < 100 && g_running; ++i) {   // ~20 s of attempts
        send_pkt(PKT_HELLO, nullptr, 0);
        for (int j = 0; j < 10; ++j) {
            if (g_verified) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    return g_verified;
}

// ----------------------------------------------------------------------------
//  main
// ----------------------------------------------------------------------------
int main() {
    std::cout << "=== P2P VOIP + CHAT + FILE ===\n";

    if (!load_key("key.txt")) {
        std::cout << "Could not read key.txt (need 64 hex chars).\n";
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cout << "WSAStartup failed.\n"; return 1;
    }

    g_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_sock == INVALID_SOCKET) { std::cout << "socket() failed.\n"; return 1; }

    // Local bind port (both peers exchange their public IP:port out of band)
    std::string localPortStr, ip, portStr;
    std::cout << "Local bind Port: ";
    std::getline(std::cin, localPortStr);
    int localPort = localPortStr.empty() ? 55555 : atoi(localPortStr.c_str());

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons((u_short)localPort);
    if (bind(g_sock, (sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        std::cout << "bind() failed.\n"; return 1;
    }

    std::cout << "Peer IP: ";   std::getline(std::cin, ip);
    std::cout << "Port: ";      std::getline(std::cin, portStr);
    int peerPort = atoi(portStr.c_str());

    // Opus codec (must exist before the receive thread decodes any voice)
    int err = 0;
    g_enc = opus_encoder_create(SAMPLE_RATE, CHANNELS, OPUS_APPLICATION_VOIP, &err);
    g_dec = opus_decoder_create(SAMPLE_RATE, CHANNELS, &err);
    if (!g_enc || !g_dec) { std::cout << "Opus init failed.\n"; return 1; }

    std::thread rx(recv_thread);

    if (!punch_and_verify(ip, peerPort)) {
        std::cout << "Peer rejected.\n";
        g_running = false;
        rx.join();
        return 1;
    }
    std::cout << ">>> CONNECTED & VERIFIED! <<<\n";

    // Start full-duplex audio
    ma_device_config cfg = ma_device_config_init(ma_device_type_duplex);
    cfg.sampleRate        = SAMPLE_RATE;
    cfg.capture.format    = ma_format_f32;
    cfg.capture.channels  = CHANNELS;
    cfg.playback.format   = ma_format_f32;
    cfg.playback.channels = CHANNELS;
    cfg.periodSizeInFrames = FRAME_SAMPLES;
    cfg.dataCallback      = audio_callback;

    ma_device device;
    bool audioOk = (ma_device_init(nullptr, &cfg, &device) == MA_SUCCESS) &&
                   (ma_device_start(&device) == MA_SUCCESS);

    std::thread sender;
    if (audioOk) {
        std::cout << "[Audio] Voice Chat Active (Opus 48kHz)\n";
        sender = std::thread(audio_sender_thread);
    } else {
        std::cout << "[Audio] Failed to initialize device. (text/file only)\n";
    }

    std::cout << "Ready! (Voice Active). Type message or /upload [file] or /testspeed\n> "
              << std::flush;

    std::string line;
    while (g_running && std::getline(std::cin, line)) {
        if (line == "/quit" || line == "/exit") break;
        else if (line == "/testspeed")            run_speedtest();
        else if (line.rfind("/upload ", 0) == 0)  upload_file(line.substr(8));
        else if (!line.empty()) {
            std::cout << "Sending: " << line << "\n";
            send_pkt(PKT_TEXT, line);
        }
        std::cout << "> " << std::flush;
    }

    // Cleanup
    g_running = false;
    if (audioOk) { ma_device_uninit(&device); if (sender.joinable()) sender.join(); }
    rx.join();
    opus_encoder_destroy(g_enc);
    opus_decoder_destroy(g_dec);
    closesocket(g_sock);
    WSACleanup();
    return 0;
}
