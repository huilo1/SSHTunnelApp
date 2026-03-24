package com.sshtunnel.tunnel

import android.util.Log
import com.sshtunnel.service.SshVpnService
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Core engine: reads IP packets from TUN fd, manages TCP/UDP sessions,
 * forwards traffic through a local SOCKS5 proxy (backed by SSH dynamic forwarding).
 */
class TunnelEngine(
    private val tunFdIn: FileInputStream,
    private val tunFdOut: FileOutputStream,
    private val socksPort: Int,
    private val dnsServer: String = "8.8.8.8"
) {
    companion object {
        private const val TAG = "TunnelEngine"
        private const val MTU = 1500
    }

    private val running = AtomicBoolean(false)
    private val tcpSessions = ConcurrentHashMap<SessionKey, TcpSession>()
    private val executor: ExecutorService = Executors.newCachedThreadPool()
    private val outputLock = Any()
    private val logBuffer get() = SshVpnService.logBuffer
    // Allow more concurrent SOCKS5 connections for better throughput
    private val connectSemaphore = Semaphore(8)

    private fun log(msg: String, e: Throwable? = null) {
        if (e != null) {
            Log.e(TAG, msg, e)
            logBuffer.append("[Tunnel/ERR] $msg: ${e.javaClass.simpleName}: ${e.message}")
        } else {
            Log.d(TAG, msg)
            logBuffer.append("[Tunnel] $msg")
        }
    }

    fun start() {
        running.set(true)
        log("Tunnel engine started (SOCKS5 port=$socksPort)")
        executor.submit { readLoop() }
    }

    fun stop() {
        running.set(false)
        log("Tunnel engine stopping, closing ${tcpSessions.size} sessions")
        tcpSessions.values.forEach { closeSession(it) }
        tcpSessions.clear()
        executor.shutdownNow()
    }

    // ── TUN read loop ──────────────────────────────────────────────

    private fun readLoop() {
        val buf = ByteArray(MTU)
        while (running.get()) {
            try {
                val len = tunFdIn.read(buf)
                if (len <= 0) continue
                val packet = buf.copyOf(len)
                handlePacket(packet, len)
            } catch (e: IOException) {
                if (running.get()) Log.e(TAG, "TUN read error", e)
                break
            }
        }
    }

    private fun handlePacket(buf: ByteArray, len: Int) {
        if (len < Packet.IP4_HEADER_MIN) return
        if (Packet.ipVersion(buf) != 4) return

        val ipHeaderLen = Packet.ipHeaderLen(buf)
        val proto = Packet.ipProtocol(buf)

        when (proto) {
            Packet.PROTO_TCP -> handleTcp(buf, len, ipHeaderLen)
            Packet.PROTO_UDP -> handleUdp(buf, len, ipHeaderLen)
        }
    }

    // ── TCP handling ───────────────────────────────────────────────

    private fun handleTcp(buf: ByteArray, len: Int, ipHeaderLen: Int) {
        val srcIp = Packet.srcAddr(buf)
        val dstIp = Packet.dstAddr(buf)
        val srcPort = Packet.srcPort(buf, ipHeaderLen)
        val dstPort = Packet.dstPort(buf, ipHeaderLen)
        val flags = Packet.tcpFlagByte(buf, ipHeaderLen)
        val seqNum = Packet.tcpSeqNum(buf, ipHeaderLen)
        val tcpHeaderLen = Packet.tcpHeaderLen(buf, ipHeaderLen)
        val payloadStart = ipHeaderLen + tcpHeaderLen
        val payloadLen = len - payloadStart

        val key = SessionKey(srcIp, srcPort, dstIp, dstPort)

        if (flags and Packet.TCP_RST != 0) {
            tcpSessions.remove(key)?.let { closeSession(it) }
            return
        }

        if (flags and Packet.TCP_SYN != 0 && flags and Packet.TCP_ACK == 0) {
            val session = TcpSession(key = key, theirSeqNum = seqNum)
            tcpSessions[key] = session

            // Send SYN-ACK
            val synAck = Packet.buildTcpPacket(
                srcIp = dstIp, dstIp = srcIp,
                srcPort = dstPort, dstPort = srcPort,
                seqNum = session.mySeqNum,
                ackNum = seqNum + 1,
                flags = Packet.TCP_SYN or Packet.TCP_ACK
            )
            writeTun(synAck)
            session.mySeqNum++
            session.theirSeqNum = seqNum + 1

            Log.d(TAG, "TCP ${Packet.intToIp(dstIp)}:$dstPort")
            executor.submit { openSocksConnection(session) }
            return
        }

        val session = tcpSessions[key] ?: return

        if (flags and Packet.TCP_ACK != 0 && session.state == TcpState.SYN_RECEIVED) {
            session.state = TcpState.ESTABLISHED
        }

        if (flags and Packet.TCP_FIN != 0) {
            session.theirSeqNum = seqNum + payloadLen.toLong() + 1
            val finAck = Packet.buildTcpPacket(
                srcIp = dstIp, dstIp = srcIp,
                srcPort = dstPort, dstPort = srcPort,
                seqNum = session.mySeqNum,
                ackNum = session.theirSeqNum,
                flags = Packet.TCP_ACK or Packet.TCP_FIN
            )
            writeTun(finAck)
            session.mySeqNum++
            tcpSessions.remove(key)
            closeSession(session)
            return
        }

        // Data
        if (payloadLen > 0 && session.state == TcpState.ESTABLISHED) {
            session.theirSeqNum = seqNum + payloadLen

            val ack = Packet.buildTcpPacket(
                srcIp = dstIp, dstIp = srcIp,
                srcPort = dstPort, dstPort = srcPort,
                seqNum = session.mySeqNum,
                ackNum = session.theirSeqNum,
                flags = Packet.TCP_ACK
            )
            writeTun(ack)

            val payload = buf.copyOfRange(payloadStart, payloadStart + payloadLen)
            // Buffer data; it will be sent in-order by the session's write thread
            synchronized(session) {
                session.pendingData.add(payload)
            }
            // Kick the write flush (single-threaded per session via flag)
            if (session.sshOutputStream != null && !session.closed.get()) {
                executor.submit { flushPendingData(session) }
            }
        }
    }

    // ── SOCKS5 connection ──────────────────────────────────────────

    private fun openSocksConnection(session: TcpSession) {
        try {
            val dstIp = session.key.dstIp
            val dstPort = session.key.dstPort
            val dstHost = Packet.intToIp(dstIp)

            connectSemaphore.acquire()
            val socket: Socket
            try {
                socket = connectViaSocks5(dstIp, dstPort)
            } finally {
                connectSemaphore.release()
            }

            session.channelObject = socket
            session.sshInputStream = socket.getInputStream()
            val os = socket.getOutputStream()

            // Flush any data buffered while SOCKS5 was connecting
            synchronized(session) {
                session.sshOutputStream = os
                for (data in session.pendingData) {
                    os.write(data)
                }
                if (session.pendingData.isNotEmpty()) {
                    os.flush()
                }
                session.pendingData.clear()
            }

            executor.submit { socksReadLoop(session) }

        } catch (e: Exception) {
            log("SOCKS5 FAILED -> ${Packet.intToIp(session.key.dstIp)}:${session.key.dstPort}", e)
            sendRst(session)
        }
    }

    private fun connectViaSocks5(dstIp: Int, dstPort: Int): Socket {
        val socket = Socket()
        socket.connect(InetSocketAddress("127.0.0.1", socksPort), 10000)

        val out = socket.getOutputStream()
        val inp = socket.getInputStream()

        // SOCKS5 greeting: version 5, 1 method (no auth)
        out.write(byteArrayOf(0x05, 0x01, 0x00))
        out.flush()

        val greetResp = ByteArray(2)
        readFully(inp, greetResp)
        if (greetResp[0] != 0x05.toByte() || greetResp[1] != 0x00.toByte()) {
            socket.close()
            throw IOException("SOCKS5 auth rejected: ${greetResp[0].toInt() and 0xFF}, ${greetResp[1].toInt() and 0xFF}")
        }

        // SOCKS5 CONNECT to IPv4 destination
        val req = byteArrayOf(
            0x05, 0x01, 0x00, 0x01, // ver, CONNECT, rsv, IPv4
            ((dstIp shr 24) and 0xFF).toByte(),
            ((dstIp shr 16) and 0xFF).toByte(),
            ((dstIp shr 8) and 0xFF).toByte(),
            (dstIp and 0xFF).toByte(),
            ((dstPort shr 8) and 0xFF).toByte(),
            (dstPort and 0xFF).toByte()
        )
        out.write(req)
        out.flush()

        // Read CONNECT response (minimum 10 bytes for IPv4 reply)
        val resp = ByteArray(10)
        readFully(inp, resp)
        if (resp[1] != 0x00.toByte()) {
            socket.close()
            throw IOException("SOCKS5 CONNECT refused: status=${resp[1].toInt() and 0xFF}")
        }

        return socket
    }

    private fun socksReadLoop(session: TcpSession) {
        val dstHost = Packet.intToIp(session.key.dstIp)
        val dstPort = session.key.dstPort
        val buf = ByteArray(MTU - 40)
        try {
            while (running.get() && !session.closed.get()) {
                val len = session.sshInputStream?.read(buf) ?: -1
                if (len <= 0) break

                val payload = buf.copyOf(len)
                val packet = Packet.buildTcpPacket(
                    srcIp = session.key.dstIp,
                    dstIp = session.key.srcIp,
                    srcPort = session.key.dstPort,
                    dstPort = session.key.srcPort,
                    seqNum = session.mySeqNum,
                    ackNum = session.theirSeqNum,
                    flags = Packet.TCP_ACK or Packet.TCP_PSH,
                    payload = payload
                )
                writeTun(packet)
                session.mySeqNum += len
            }
        } catch (e: Exception) {
            if (!session.closed.get()) {
                Log.d(TAG, "SOCKS read ended for session", e)
            }
        }

        if (!session.closed.get()) {
            val fin = Packet.buildTcpPacket(
                srcIp = session.key.dstIp,
                dstIp = session.key.srcIp,
                srcPort = session.key.dstPort,
                dstPort = session.key.srcPort,
                seqNum = session.mySeqNum,
                ackNum = session.theirSeqNum,
                flags = Packet.TCP_FIN or Packet.TCP_ACK
            )
            writeTun(fin)
            session.mySeqNum++
            tcpSessions.remove(session.key)
            closeSession(session)
        }
    }

    // ── UDP / DNS handling ─────────────────────────────────────────

    private fun handleUdp(buf: ByteArray, len: Int, ipHeaderLen: Int) {
        val srcIp = Packet.srcAddr(buf)
        val dstIp = Packet.dstAddr(buf)
        val srcPort = Packet.srcPort(buf, ipHeaderLen)
        val dstPort = Packet.dstPort(buf, ipHeaderLen)

        val udpPayloadStart = ipHeaderLen + Packet.UDP_HEADER_SIZE
        val udpPayloadLen = len - udpPayloadStart
        if (udpPayloadLen <= 0) return

        val payload = buf.copyOfRange(udpPayloadStart, udpPayloadStart + udpPayloadLen)

        executor.submit {
            try {
                val targetHost = if (dstPort == 53) dnsServer else Packet.intToIp(dstIp)
                val targetIp = Packet.ipToInt(targetHost)
                val targetPort = dstPort

                connectSemaphore.acquire()
                val socket: Socket
                try {
                    socket = connectViaSocks5(targetIp, targetPort)
                } finally {
                    connectSemaphore.release()
                }

                val os = socket.getOutputStream()
                val ins = socket.getInputStream()

                if (dstPort == 53) {
                    // DNS over TCP: prepend 2-byte length
                    val tcpDns = ByteArray(payload.size + 2)
                    tcpDns[0] = ((payload.size shr 8) and 0xFF).toByte()
                    tcpDns[1] = (payload.size and 0xFF).toByte()
                    System.arraycopy(payload, 0, tcpDns, 2, payload.size)
                    os.write(tcpDns)
                    os.flush()

                    val lenBuf = ByteArray(2)
                    readFully(ins, lenBuf)
                    val respLen = ((lenBuf[0].toInt() and 0xFF) shl 8) or (lenBuf[1].toInt() and 0xFF)
                    val respBuf = ByteArray(respLen)
                    readFully(ins, respBuf)

                    val response = Packet.buildUdpPacket(
                        srcIp = dstIp, dstIp = srcIp,
                        srcPort = dstPort, dstPort = srcPort,
                        payload = respBuf
                    )
                    writeTun(response)
                } else {
                    os.write(payload)
                    os.flush()
                    val respBuf = ByteArray(MTU)
                    val respLen = ins.read(respBuf)
                    if (respLen > 0) {
                        val response = Packet.buildUdpPacket(
                            srcIp = dstIp, dstIp = srcIp,
                            srcPort = dstPort, dstPort = srcPort,
                            payload = respBuf.copyOf(respLen)
                        )
                        writeTun(response)
                    }
                }
                socket.close()
            } catch (e: Exception) {
                Log.d(TAG, "UDP forward failed for ${Packet.intToIp(dstIp)}:$dstPort", e)
            }
        }
    }

    // ── Utility ────────────────────────────────────────────────────

    private fun flushPendingData(session: TcpSession) {
        try {
            val os = session.sshOutputStream ?: return
            val toSend: List<ByteArray>
            synchronized(session) {
                if (session.pendingData.isEmpty()) return
                toSend = session.pendingData.toList()
                session.pendingData.clear()
            }
            for (data in toSend) {
                os.write(data)
            }
            os.flush()
        } catch (e: Exception) {
            if (!session.closed.get()) {
                Log.e(TAG, "SOCKS write error", e)
                sendRst(session)
            }
        }
    }

    private fun readFully(inp: InputStream, buf: ByteArray) {
        var offset = 0
        while (offset < buf.size) {
            val n = inp.read(buf, offset, buf.size - offset)
            if (n <= 0) throw IOException("Unexpected EOF in SOCKS5")
            offset += n
        }
    }

    private fun sendRst(session: TcpSession) {
        val rst = Packet.buildTcpPacket(
            srcIp = session.key.dstIp,
            dstIp = session.key.srcIp,
            srcPort = session.key.dstPort,
            dstPort = session.key.srcPort,
            seqNum = session.mySeqNum,
            ackNum = session.theirSeqNum,
            flags = Packet.TCP_RST or Packet.TCP_ACK
        )
        writeTun(rst)
        tcpSessions.remove(session.key)
        closeSession(session)
    }

    private fun closeSession(session: TcpSession) {
        if (!session.closed.compareAndSet(false, true)) return
        try { session.sshInputStream?.close() } catch (_: Exception) {}
        try { session.sshOutputStream?.close() } catch (_: Exception) {}
        try { (session.channelObject as? Socket)?.close() } catch (_: Exception) {}
    }

    private fun writeTun(packet: ByteArray) {
        synchronized(outputLock) {
            try {
                tunFdOut.write(packet)
                tunFdOut.flush()
            } catch (e: IOException) {
                if (running.get()) Log.e(TAG, "TUN write error", e)
            }
        }
    }
}
