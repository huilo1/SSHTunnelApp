package com.sshtunnel.service

import android.net.VpnService
import com.jcraft.jsch.SocketFactory
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Socket factory that protects sockets from being routed through the VPN.
 * This prevents the SSH connection itself from going through the tunnel (infinite loop).
 */
class ProtectedSocketFactory(private val vpnService: VpnService) : SocketFactory {

    override fun createSocket(host: String, port: Int): Socket {
        val socket = Socket()
        vpnService.protect(socket)
        socket.connect(InetSocketAddress(host, port), 15000)
        return socket
    }

    override fun getInputStream(socket: Socket): InputStream = socket.getInputStream()

    override fun getOutputStream(socket: Socket): OutputStream = socket.getOutputStream()
}
