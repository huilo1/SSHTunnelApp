package com.sshtunnel.data

import java.util.UUID

data class ServerProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String = "",
    val host: String = "",
    val port: Int = 22,
    val username: String = "",
    val authMethod: AuthMethod = AuthMethod.PASSWORD,
    val password: String = "",
    val privateKey: String = "",
    val keyPassphrase: String = "",
    val dnsServer: String = "8.8.8.8",
    val tunnelMode: TunnelMode = TunnelMode.SOCKS5
)

enum class AuthMethod {
    PASSWORD, KEY
}

enum class TunnelMode {
    SOCKS5,   // SOCKS5 proxy via exec + port forward (works through DPI)
    SSH_TUN   // True VPN via ssh -w style TUN device (requires PermitTunnel yes + root/sudo)
}
