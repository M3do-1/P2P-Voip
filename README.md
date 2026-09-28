# Encrypted Peer-to-Peer VoIP & File-Transfer System

A **serverless** peer-to-peer communication tool for Windows. Two clients connect
**directly** to each other across the internet — no central server, no relay —
using **UDP NAT hole-punching**, and exchange **encrypted real-time voice, text
messages, and files** over that direct link.

**Built with:** C++17 · Winsock2 · Opus · OpenSSL (AES-256-GCM) · miniaudio

---

## Features

- **Direct P2P connection** — NAT hole-punching opens a path straight through
  home/office routers, so traffic never touches a middleman server.
- **Real-time voice chat** — Opus codec, 48 kHz mono, low latency.
- **Text chat** — send a message any time during a call.
- **File transfer** — `/upload <file>`, with reliable chunked delivery over UDP.
- **End-to-end encryption** — every packet is sealed with AES-256-GCM. A shared
  key (`key.txt`) also serves as authentication: a peer with the wrong key can't
  produce a valid packet, so the handshake is rejected.
- **Built-in speed test** — `/testspeed` benchmarks the link throughput.

---

## Requirements

| Component | Why it's needed | Where to get it |
|-----------|-----------------|-----------------|
| **Windows 10/11 (x64)** | Uses Winsock + WASAPI audio | — |
| **Visual Studio 2019/2022** (Community is free) | C++ compiler (MSVC) + Windows SDK | https://visualstudio.microsoft.com/ — during install, check **"Desktop development with C++"** |
| **Opus** (`opus.h` + `opus.lib`) | Voice codec | Easiest via vcpkg (below), or source at https://opus-codec.org/ / https://github.com/xiph/opus |
| **OpenSSL 3.x** (`openssl/*.h` + `libcrypto.lib`) | AES-256-GCM encryption | Easiest via vcpkg (below), or prebuilt Windows binaries at https://slproweb.com/products/Win32OpenSSL.html |
| **miniaudio** (`miniaudio.h`) | Microphone capture + speaker playback (single header file) | https://github.com/mackron/miniaudio — download `miniaudio.h` |
| **CMake** (optional) | Alternative to the Visual Studio GUI | https://cmake.org/download/ |
| **vcpkg** (recommended) | Fetches Opus + OpenSSL automatically | https://github.com/microsoft/vcpkg |

> `curl` (used to display your public IP) ships with Windows 10 (1803+) and 11,
> so you don't need to install it.

---

## Getting the dependencies

You need **headers and import libraries** for Opus and OpenSSL to *build*, and
their **DLLs** to *run*. The recommended route grabs everything at once.

### Recommended: vcpkg (handles Opus + OpenSSL for you)

```powershell
git clone https://github.com/microsoft/vcpkg
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg install opus:x64-windows openssl:x64-windows
.\vcpkg integrate install
```

`vcpkg integrate install` makes the headers and libs available to Visual Studio
automatically — no manual include/lib paths needed.

### Then grab miniaudio (header-only)

Download **`miniaudio.h`** from
https://github.com/mackron/miniaudio/blob/master/miniaudio.h (click **Raw**,
save it) and drop it in the same folder as `NatPuncher.cpp`.

### Manual alternative (no vcpkg)

- **OpenSSL:** install the **Win64 OpenSSL v3.x** package from
  https://slproweb.com/products/Win32OpenSSL.html. Note its `include\` and
  `lib\` folders.
- **Opus:** build from https://github.com/xiph/opus, or use a prebuilt x64
  package, and note its `include\` and `lib\` folders.
- You'll then point the compiler at those folders manually (see the build
  steps below).

---

## Building

### Option A — Visual Studio (matches the original toolchain)

1. Open Visual Studio → **Create a new project** → **Console App (C++)** →
   set the platform to **x64** and configuration to **Release**.
2. Add `NatPuncher.cpp` to the project, and place `miniaudio.h` next to it.
3. If you used **vcpkg** with `integrate install`, you're done — skip to step 5.
4. If you're doing it **manually**, open **Project → Properties** and set:
   - *C/C++ → General → Additional Include Directories:* your Opus and OpenSSL
     `include\` folders.
   - *Linker → Input → Additional Dependencies:* add
     `opus.lib;libcrypto.lib;ws2_32.lib`.
   - *Linker → General → Additional Library Directories:* your Opus and OpenSSL
     `lib\` folders.
5. **Build** (Ctrl+Shift+B).

### Option B — CMake

```powershell
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=<path-to-vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

The compiled `NatPuncher.exe` lands in `build\Release\`.

---

## Running

### 1. Assemble the run folder

Put these four files together in one folder:

```
NatPuncher.exe
opus.dll                 (from your Opus install)
libcrypto-3-x64.dll      (from your OpenSSL install)
key.txt                  (the shared encryption key — see below)
```

> If Windows complains about a missing `VCRUNTIME140.dll` / `MSVCP140.dll`,
> install the **Microsoft Visual C++ Redistributable (x64)** from
> https://aka.ms/vs/17/release/vc_redist.x64.exe.

### 2. Create the shared key

`key.txt` holds a single line of **64 hexadecimal characters** (a 256-bit AES
key). Both people must use the **exact same** `key.txt`. Generate one with:

```powershell
# PowerShell one-liner: 32 random bytes as hex
-join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) }) > key.txt
```

Share `key.txt` with your peer over a **secure** channel (not the same network
you're about to chat on).

### 3. Connect (this needs TWO machines on TWO networks)

Because it's peer-to-peer, you can't fully test it on one computer — you need a
second person (or a second machine on a different internet connection, e.g. a
laptop on a phone hotspot).

On **both** machines:

1. Run `NatPuncher.exe`.
2. Enter the **same port** on both sides (e.g. `55555`).
3. The app prints your **public IP**. Swap public IPs with your peer.
4. Each side enters the **other's** public IP.
5. Press Enter on both at roughly the **same time** — hole-punching needs both
   ends firing packets at each other within a few seconds.

On success:

```
=== P2P VOIP + CHAT + FILE ===
Enter the Port to bind (Shared with friend): 55555
Your Public IP is: 203.0.113.42
Enter Friend's Public IP: 198.51.100.9
Punching NAT to 198.51.100.9:55555...
>>> CONNECTED & VERIFIED! <<<
[Audio] Voice Chat Active (Opus 48kHz)
Ready! (Voice Active). Type message or /upload [file] or /testspeed
>
```

### Quick LAN test (skips NAT)

To verify voice/chat/transfer without dealing with NAT, run it on two computers
on the **same WiFi** and enter each other's **local** IPs (`192.168.x.x`), same
port. On a LAN no hole-punching is required, so this isolates the app logic from
the networking.

---

## Commands

| Input | Action |
|-------|--------|
| *(any text)* | Send a chat message to your peer |
| `/upload <path>` | Send a file (saved on the other side as `recv_<name>`) |
| `/testspeed` | Run the 100 MB throughput benchmark |
| `exit` | Quit |

---

## How it works

```
   You                                             Peer
 ┌───────┐   1. PUNCH packets (both directions)  ┌───────┐
 │  App  │ ─────────────────────────────────────▶│  App  │
 │       │◀───────────────────────────────────── │       │
 └───┬───┘   2. First packet through = connected └───┬───┘
     │                                               │
     │   3. Encrypted stream (AES-256-GCM):          │
     │      • Opus voice frames                      │
     │      • text messages                          │
     │      • file chunks                            │
     ▼                                               ▼
  mic/speaker                                    mic/speaker
```

- **NAT hole-punching:** both peers send UDP packets to each other's public
  `IP:port` at the same time. Each outbound packet makes the sender's router
  expect a reply, so when the other side's packet arrives the router lets it in
  — a direct path forms without any server in between.
- **Keep-alive:** a periodic heartbeat keeps the router's port mapping open so
  the connection doesn't silently die during quiet moments.
- **Encryption + auth:** each packet is `AES-256-GCM(nonce, payload)`. GCM's
  authentication tag means a packet only decrypts if the sender holds the same
  256-bit key — so encryption and peer authentication are the same step.

---

## Troubleshooting

- **`Bind failed. Port is busy/tainted.`** — another program holds that port, or
  the OS is cooling it down. Try the next number (`55556`, `55557`, …) on both
  sides.
- **`Timed out.`** — the punch didn't get through. Usual causes:
  - You didn't start both sides close enough in time — retry together.
  - One side is behind a **symmetric NAT** (common on mobile data and some
    corporate networks), which randomizes ports and defeats basic hole-punching.
    Fix by **port-forwarding** one side's chosen port to their machine, or test
    from a different network.
  - A firewall is blocking UDP — allow the app through Windows Firewall.
- **`Peer rejected.` / no audio but connected** — your `key.txt` files don't
  match. Both sides must use the identical key.

---

## Security notes

This is a personal project; a couple of design trade-offs are worth knowing:

- The key is a **static pre-shared secret** stored in plaintext (`key.txt`). Fine
  for a private link between two people, but a production system would negotiate
  a fresh key per session (e.g. X25519 ECDH) instead of shipping a fixed file.
- There's no replay protection beyond GCM's random per-packet nonce; a sequence
  number / sliding window would harden it further.

---

## Tech stack

**Language:** C++17 · **Networking:** Winsock2 (UDP), custom NAT hole-punching
protocol · **Audio:** Opus codec + miniaudio (WASAPI) · **Crypto:** OpenSSL
AES-256-GCM · **Concurrency:** multithreaded (listener / heartbeat / audio /
input threads with atomic state).