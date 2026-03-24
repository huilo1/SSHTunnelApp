package com.sshtunnel.tunnel

import android.util.Log
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import com.sshtunnel.service.SshVpnService
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Core engine: reads IP packets from TUN fd, manages TCP/UDP sessions,
 * forwards traffic through SSH channels.
 */
class TunnelEngine(
    private val tunFdIn: FileInputStream,
    private val tunFdOut: FileOutputStream,
    private val sshSession: Session,
    private val dnsServer: String = "8.8.8.8",
    private val protectSocket: (Int) -> Boolean
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
        log("Tunnel engine started")
        executor.submit { readLoop() }
    }

    fun stop() {
        running.set(false)
        log("Tunnel engine stopping, closing ${tcpSessions.size} sessions")
        tcpSessions.values.forEach { closeSession(it) }
        tcpSessions.clear()
        executor.shutdownNow()
    }

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

    private fun handleTcp(buf: ByteArray, len: Int, ipHeaderLen: Int) {
        val srcIp = Packet.srcAddr(buf)
        val dstIp = Packet.dstAddr(buf)
        val srcPort = Packet.srcPort(buf, ipHeaderLen)
        val dstPort = Packet.dstPort(buf, ipHeaderLen)
        val flags = Packet.tcpFlagByte(buf, ipHeaderLen)
        val seqNum = Packet.tcpSeqNum(buf, ipHeaderLen)
        val ackNum = Packet.tcpAckNum(buf, ipHeaderLen)
        val tcpHeaderLen = Packet.tcpHeaderLen(buf, ipHeaderLen)
        val payloadStart = ipHeaderLen + tcpHeaderLen
        val payloadLen = len - payloadStart

        val key = SessionKey(srcIp, srcPort, dstIp, dstPort)

        if (flags and Packet.TCP_RST != 0) {
            tcpSessions.remove(key)?.let { closeSession(it) }
            return
        }

        if (flags and Packet.TCP_SYN != 0 && flags and Packet.TCP_ACK == 0) {
            // New connection
            val session = TcpSession(
                key = key,
                theirSeqNum = seqNum
            )
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

            // Open SSH channel in background
            log("New TCP: ${Packet.intToIp(srcIp)}:$srcPort -> ${Packet.intToIp(dstIp)}:$dstPort")
            executor.submit { openSshChannel(session) }
            return
        }

        val session = tcpSessions[key] ?: return

        if (flags and Packet.TCP_ACK != 0 && session.state == TcpState.SYN_RECEIVED) {
            session.state = TcpState.ESTABLISHED
        }

        if (flags and Packet.TCP_FIN != 0) {
            session.theirSeqNum = seqNum + payloadLen.toLong() + 1
            // Send ACK for FIN
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

            // ACK the data
            val ack = Packet.buildTcpPacket(
                srcIp = dstIp, dstIp = srcIp,
                srcPort = dstPort, dstPort = srcPort,
                seqNum = session.mySeqNum,
                ackNum = session.theirSeqNum,
                flags = Packet.TCP_ACK
            )
            writeTun(ack)

            // Forward data through SSH
            val payload = buf.copyOfRange(payloadStart, payloadStart + payloadLen)
            executor.submit {
                try {
                    session.sshOutputStream?.write(payload)
                    session.sshOutputStream?.flush()
                } catch (e: Exception) {
                    Log.e(TAG, "SSH write error", e)
                    sendRst(session)
                }
            }
        }
    }

    private fun openSshChannel(session: TcpSession) {
        try {
            val dstHost = Packet.intToIp(session.key.dstIp)
            val dstPort = session.key.dstPort

            log("Opening SSH channel -> $dstHost:$dstPort")
            val channel = sshSession.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost(dstHost)
            channel.setPort(dstPort)
            channel.connect(10000)
            log("SSH channel connected -> $dstHost:$dstPort")

            session.sshOutputStream = channel.outputStream
            session.sshInputStream = channel.inputStream
            session.channelObject = channel

            // Read SSH responses and send back through TUN
            executor.submit { sshReadLoop(session) }

        } catch (e: Exception) {
            log("SSH channel FAILED -> ${Packet.intToIp(session.key.dstIp)}:${session.key.dstPort}", e)
            sendRst(session)
        }
    }

    private fun sshReadLoop(session: TcpSession) {
        val buf = ByteArray(MTU - 40) // Leave room for IP+TCP headers
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
                Log.d(TAG, "SSH read ended for session", e)
            }
        }

        // Connection ended from remote side, send FIN
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

    private fun handleUdp(buf: ByteArray, len: Int, ipHeaderLen: Int) {
        val srcIp = Packet.srcAddr(buf)
        val dstIp = Packet.dstAddr(buf)
        val srcPort = Packet.srcPort(buf, ipHeaderLen)
        val dstPort = Packet.dstPort(buf, ipHeaderLen)

        val udpPayloadStart = ipHeaderLen + Packet.UDP_HEADER_SIZE
        val udpPayloadLen = len - udpPayloadStart
        if (udpPayloadLen <= 0) return

        val payload = buf.copyOfRange(udpPayloadStart, udpPayloadStart + udpPayloadLen)

        // Forward all UDP (including DNS) through SSH
        log("UDP: ${Packet.intToIp(srcIp)}:$srcPort -> ${Packet.intToIp(dstIp)}:$dstPort (${udpPayloadLen}b)")
        executor.submit {
            try {
                val targetHost = if (dstPort == 53) dnsServer else Packet.intToIp(dstIp)
                val targetPort = dstPort

                val channel = sshSession.openChannel("direct-tcpip") as ChannelDirectTCPIP
                channel.setHost(targetHost)
                channel.setPort(targetPort)

                if (dstPort == 53) {
                    // DNS over TCP: prepend 2-byte length
                    channel.connect(5000)
                    val os = channel.outputStream
                    val tcpDns = ByteArray(payload.size + 2)
                    tcpDns[0] = ((payload.size shr 8) and 0xFF).toByte()
                    tcpDns[1] = (payload.size and 0xFF).toByte()
                    System.arraycopy(payload, 0, tcpDns, 2, payload.size)
                    os.write(tcpDns)
                    os.flush()

                    val ins = channel.inputStream
                    // Read 2-byte length prefix
                    val lenBuf = ByteArray(2)
                    var read = 0
                    while (read < 2) {
                        val r = ins.read(lenBuf, read, 2 - read)
                        if (r <= 0) break
                        read += r
                    }
                    if (read == 2) {
                        val respLen = ((lenBuf[0].toInt() and 0xFF) shl 8) or (lenBuf[1].toInt() and 0xFF)
                        val respBuf = ByteArray(respLen)
                        read = 0
                        while (read < respLen) {
                            val r = ins.read(respBuf, read, respLen - read)
                            if (r <= 0) break
                            read += r
                        }
                        if (read == respLen) {
                            val response = Packet.buildUdpPacket(
                                srcIp = dstIp, dstIp = srcIp,
                                srcPort = dstPort, dstPort = srcPort,
                                payload = respBuf
                            )
                            writeTun(response)
                        }
                    }
                    channel.disconnect()
                } else {
                    // Non-DNS UDP - best effort through TCP channel
                    channel.connect(5000)
                    channel.outputStream.write(payload)
                    channel.outputStream.flush()

                    val respBuf = ByteArray(MTU)
                    val respLen = channel.inputStream.read(respBuf)
                    if (respLen > 0) {
                        val response = Packet.buildUdpPacket(
                            srcIp = dstIp, dstIp = srcIp,
                            srcPort = dstPort, dstPort = srcPort,
                            payload = respBuf.copyOf(respLen)
                        )
                        writeTun(response)
                    }
                    channel.disconnect()
                }
            } catch (e: Exception) {
                Log.d(TAG, "UDP forward failed for ${Packet.intToIp(dstIp)}:$dstPort", e)
            }
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
        try { (session.channelObject as? ChannelDirectTCPIP)?.disconnect() } catch (_: Exception) {}
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
