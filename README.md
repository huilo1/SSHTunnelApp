# SSH Tunnel VPN for Android

Android app that creates an SSH tunnel and routes **all device traffic** through it (acts as a VPN).

## Architecture

```
┌─────────────────────┐
│   Android Device    │
│                     │
│  ┌───────────────┐  │     ┌──────────────┐
│  │  VpnService   │──┼────▶│  SSH Server   │──▶ Internet
│  │  (TUN iface)  │  │     │  (OpenSSH)    │
│  └───────┬───────┘  │     └──────────────┘
│          │          │
│  ┌───────▼───────┐  │
│  │ TunnelEngine  │  │
│  │ (packet parse │  │
│  │  + forward)   │  │
│  └───────┬───────┘  │
│          │          │
│  ┌───────▼───────┐  │
│  │  JSch SSH     │  │
│  │ direct-tcpip  │  │
│  │  channels     │  │
│  └───────────────┘  │
└─────────────────────┘
```

### How it works

1. **VPNService** creates a TUN interface and captures all device IP traffic
2. **TunnelEngine** reads raw IP packets from TUN, parses IP/TCP/UDP headers
3. For each **TCP connection**: opens a JSch `direct-tcpip` SSH channel to the destination
4. For **UDP/DNS**: forwards DNS queries through SSH as DNS-over-TCP
5. Response packets are constructed and written back to TUN
6. The SSH socket itself is **protected** via `VpnService.protect()` to avoid routing loops

### Key components

| File | Purpose |
|------|---------|
| `SshVpnService.kt` | Android VpnService, manages SSH session lifecycle, foreground notification |
| `ProtectedSocketFactory.kt` | JSch SocketFactory that calls `protect()` on the SSH socket |
| `TunnelEngine.kt` | Core packet engine: TUN ↔ SSH channel forwarding |
| `Packet.kt` | IP/TCP/UDP packet parser and constructor (checksums, headers) |
| `TcpSession.kt` | TCP session state tracking |
| `ProfileRepository.kt` | SharedPreferences-based storage for server profiles |
| `ServerProfile.kt` | Data class for SSH server configuration |
| `MainActivity.kt` | UI: server list, connect/disconnect, live log viewer |
| `ServerAdapter.kt` | RecyclerView adapter for server profiles |

## Features

- Multiple server profiles with persistent storage
- Authentication: **password** or **SSH key** (RSA, ECDSA, Ed25519)
- Ed25519 support via EdDSA + BouncyCastle security providers
- Configurable DNS server per profile
- All traffic (TCP + DNS) routed through SSH tunnel
- Live connection log viewer (tap toolbar title)
- Copy logs to clipboard for debugging
- Foreground service with persistent notification

## Build

Requirements: JDK 17, Android SDK 34, Build Tools 34.0.0

```bash
export JAVA_HOME=/path/to/jdk17
export ANDROID_HOME=/path/to/android-sdk
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

Min SDK: 28 (Android 9), Target SDK: 34

## Dependencies

- `com.github.mwiede:jsch:0.2.17` — SSH client (modern JSch fork with ed25519)
- `net.i2p.crypto:eddsa:0.3.0` — Ed25519 security provider for Android < 13
- `org.bouncycastle:bcprov-jdk18on:1.77` — Full BouncyCastle for curve25519/chacha20
- `com.google.code.gson:gson:2.10.1` — JSON serialization for profiles
- AndroidX, Material Design 3

## Current Status — DEBUGGING

### What works
- SSH connection with ed25519 key authentication ✅
- VPN TUN interface setup ✅
- Packet capture and parsing from TUN ✅
- TCP SYN detection, session creation ✅
- UDP/DNS interception ✅
- Live log viewer in UI ✅

### What's broken
- **All `direct-tcpip` SSH channels fail with `channel is not opened` (10s timeout)**
- No traffic actually flows through the tunnel
- DNS queries are intercepted but forwarded via direct-tcpip which also fails

### Diagnostic build (current)

The current build includes diagnostic tests that run right after SSH authentication:

1. **Test direct-tcpip BEFORE VPN** — opens a channel to 8.8.8.8:53 before TUN is established
2. **Test exec channel** — runs `echo tunnel_test_ok` via SSH exec
3. **Test direct-tcpip AFTER VPN** — opens a channel after TUN is established

This determines whether:
- **BEFORE=FAIL** → Server blocks TCP forwarding for this user (check `AllowTcpForwarding` in sshd_config, Match blocks, PAM restrictions)
- **BEFORE=OK, AFTER=FAIL** → VPN establishment breaks SSH session routing (protect() issue)
- **BOTH=OK** → Issue is in TunnelEngine's channel handling (concurrency, threading)

### Server configuration checks

Check `AllowTcpForwarding`, user-specific `Match` blocks, key restrictions, and keepalive settings on your own SSH server.

### Likely root causes to investigate

1. **Server-side forwarding block** — despite config looking OK, something may restrict `direct-tcpip` for the SSH user. Test: `ssh -N -L 8888:google.com:80 user@example.com` from another machine
2. **VPN breaks SSH socket routing** — `protect()` may not fully prevent VPN from capturing SSH session traffic after TUN is established
3. **JSch threading issue** — channel open confirmation messages not dispatched; try with `session.setPortForwardingD()` (SOCKS proxy) as alternative

### Alternative approach if direct-tcpip doesn't work

Switch from per-connection `direct-tcpip` channels to:
1. `session.setPortForwardingD(socksPort)` — JSch creates SOCKS5 proxy
2. For each TCP connection from TUN, open `java.net.Socket(Proxy.SOCKS)` to localhost:socksPort
3. Localhost traffic bypasses Android VPN (not routed through TUN)

This uses the same underlying SSH mechanism but through JSch's more battle-tested SOCKS implementation.
