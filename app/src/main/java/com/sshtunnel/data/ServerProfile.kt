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
    val dnsServer: String = "8.8.8.8"
)

enum class AuthMethod {
    PASSWORD, KEY
}
