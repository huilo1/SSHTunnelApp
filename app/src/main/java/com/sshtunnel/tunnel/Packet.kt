package com.sshtunnel.tunnel

import java.nio.ByteBuffer

/**
 * Minimal IP/TCP/UDP packet parsing and construction for the VPN TUN interface.
 */
object Packet {

    const val IP4_HEADER_MIN = 20
    const val TCP_HEADER_MIN = 20
    const val UDP_HEADER_SIZE = 8
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    fun ipVersion(buf: ByteArray): Int = (buf[0].toInt() shr 4) and 0xF
    fun ipHeaderLen(buf: ByteArray): Int = (buf[0].toInt() and 0xF) * 4
    fun ipTotalLen(buf: ByteArray): Int = ((buf[2].toInt() and 0xFF) shl 8) or (buf[3].toInt() and 0xFF)
    fun ipProtocol(buf: ByteArray): Int = buf[9].toInt() and 0xFF

    fun srcAddr(buf: ByteArray): Int =
        ((buf[12].toInt() and 0xFF) shl 24) or ((buf[13].toInt() and 0xFF) shl 16) or
        ((buf[14].toInt() and 0xFF) shl 8) or (buf[15].toInt() and 0xFF)

    fun dstAddr(buf: ByteArray): Int =
        ((buf[16].toInt() and 0xFF) shl 24) or ((buf[17].toInt() and 0xFF) shl 16) or
        ((buf[18].toInt() and 0xFF) shl 8) or (buf[19].toInt() and 0xFF)

    fun intToIp(ip: Int): String =
        "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"

    fun ipToInt(ip: String): Int {
        val parts = ip.split(".")
        return (parts[0].toInt() shl 24) or (parts[1].toInt() shl 16) or
               (parts[2].toInt() shl 8) or parts[3].toInt()
    }

    fun srcPort(buf: ByteArray, ipHeaderLen: Int): Int =
        ((buf[ipHeaderLen].toInt() and 0xFF) shl 8) or (buf[ipHeaderLen + 1].toInt() and 0xFF)

    fun dstPort(buf: ByteArray, ipHeaderLen: Int): Int =
        ((buf[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or (buf[ipHeaderLen + 3].toInt() and 0xFF)

    // TCP flags
    fun tcpFlags(buf: ByteArray, ipHeaderLen: Int): Int =
        ((buf[ipHeaderLen + 12].toInt() and 0xFF) shl 8) or (buf[ipHeaderLen + 13].toInt() and 0xFF)

    fun tcpHeaderLen(buf: ByteArray, ipHeaderLen: Int): Int =
        ((buf[ipHeaderLen + 12].toInt() and 0xFF) shr 4) * 4

    fun tcpSeqNum(buf: ByteArray, ipHeaderLen: Int): Long {
        val off = ipHeaderLen + 4
        return ((buf[off].toLong() and 0xFF) shl 24) or ((buf[off + 1].toLong() and 0xFF) shl 16) or
               ((buf[off + 2].toLong() and 0xFF) shl 8) or (buf[off + 3].toLong() and 0xFF)
    }

    fun tcpAckNum(buf: ByteArray, ipHeaderLen: Int): Long {
        val off = ipHeaderLen + 8
        return ((buf[off].toLong() and 0xFF) shl 24) or ((buf[off + 1].toLong() and 0xFF) shl 16) or
               ((buf[off + 2].toLong() and 0xFF) shl 8) or (buf[off + 3].toLong() and 0xFF)
    }

    const val TCP_SYN = 0x02
    const val TCP_ACK = 0x10
    const val TCP_FIN = 0x01
    const val TCP_RST = 0x04
    const val TCP_PSH = 0x08

    fun tcpFlagByte(buf: ByteArray, ipHeaderLen: Int): Int = buf[ipHeaderLen + 13].toInt() and 0xFF

    /**
     * Build an IP+TCP response packet.
     */
    fun buildTcpPacket(
        srcIp: Int, dstIp: Int,
        srcPort: Int, dstPort: Int,
        seqNum: Long, ackNum: Long,
        flags: Int,
        payload: ByteArray = ByteArray(0),
        windowSize: Int = 65535
    ): ByteArray {
        val ipHeaderLen = 20
        val tcpHeaderLen = 20
        val totalLen = ipHeaderLen + tcpHeaderLen + payload.size
        val buf = ByteArray(totalLen)

        // IP header
        buf[0] = 0x45.toByte() // version=4, ihl=5
        buf[2] = ((totalLen shr 8) and 0xFF).toByte()
        buf[3] = (totalLen and 0xFF).toByte()
        buf[8] = 64.toByte() // TTL
        buf[9] = PROTO_TCP.toByte()
        buf[12] = ((srcIp shr 24) and 0xFF).toByte()
        buf[13] = ((srcIp shr 16) and 0xFF).toByte()
        buf[14] = ((srcIp shr 8) and 0xFF).toByte()
        buf[15] = (srcIp and 0xFF).toByte()
        buf[16] = ((dstIp shr 24) and 0xFF).toByte()
        buf[17] = ((dstIp shr 16) and 0xFF).toByte()
        buf[18] = ((dstIp shr 8) and 0xFF).toByte()
        buf[19] = (dstIp and 0xFF).toByte()

        // IP checksum
        val ipCksum = ipChecksum(buf, 0, ipHeaderLen)
        buf[10] = ((ipCksum shr 8) and 0xFF).toByte()
        buf[11] = (ipCksum and 0xFF).toByte()

        // TCP header
        val t = ipHeaderLen
        buf[t] = ((srcPort shr 8) and 0xFF).toByte()
        buf[t + 1] = (srcPort and 0xFF).toByte()
        buf[t + 2] = ((dstPort shr 8) and 0xFF).toByte()
        buf[t + 3] = (dstPort and 0xFF).toByte()
        // seq
        buf[t + 4] = ((seqNum shr 24) and 0xFF).toByte()
        buf[t + 5] = ((seqNum shr 16) and 0xFF).toByte()
        buf[t + 6] = ((seqNum shr 8) and 0xFF).toByte()
        buf[t + 7] = (seqNum and 0xFF).toByte()
        // ack
        buf[t + 8] = ((ackNum shr 24) and 0xFF).toByte()
        buf[t + 9] = ((ackNum shr 16) and 0xFF).toByte()
        buf[t + 10] = ((ackNum shr 8) and 0xFF).toByte()
        buf[t + 11] = (ackNum and 0xFF).toByte()
        // data offset (5 words = 20 bytes) + reserved
        buf[t + 12] = 0x50.toByte()
        // flags
        buf[t + 13] = flags.toByte()
        // window
        buf[t + 14] = ((windowSize shr 8) and 0xFF).toByte()
        buf[t + 15] = (windowSize and 0xFF).toByte()

        // copy payload
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, buf, t + tcpHeaderLen, payload.size)
        }

        // TCP checksum (with pseudo-header)
        val tcpCksum = tcpChecksum(buf, ipHeaderLen, totalLen - ipHeaderLen, srcIp, dstIp)
        buf[t + 16] = ((tcpCksum shr 8) and 0xFF).toByte()
        buf[t + 17] = (tcpCksum and 0xFF).toByte()

        return buf
    }

    fun buildUdpPacket(
        srcIp: Int, dstIp: Int,
        srcPort: Int, dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val ipHeaderLen = 20
        val udpLen = UDP_HEADER_SIZE + payload.size
        val totalLen = ipHeaderLen + udpLen
        val buf = ByteArray(totalLen)

        // IP header
        buf[0] = 0x45.toByte()
        buf[2] = ((totalLen shr 8) and 0xFF).toByte()
        buf[3] = (totalLen and 0xFF).toByte()
        buf[8] = 64.toByte()
        buf[9] = PROTO_UDP.toByte()
        buf[12] = ((srcIp shr 24) and 0xFF).toByte()
        buf[13] = ((srcIp shr 16) and 0xFF).toByte()
        buf[14] = ((srcIp shr 8) and 0xFF).toByte()
        buf[15] = (srcIp and 0xFF).toByte()
        buf[16] = ((dstIp shr 24) and 0xFF).toByte()
        buf[17] = ((dstIp shr 16) and 0xFF).toByte()
        buf[18] = ((dstIp shr 8) and 0xFF).toByte()
        buf[19] = (dstIp and 0xFF).toByte()

        val ipCksum = ipChecksum(buf, 0, ipHeaderLen)
        buf[10] = ((ipCksum shr 8) and 0xFF).toByte()
        buf[11] = (ipCksum and 0xFF).toByte()

        // UDP header
        val u = ipHeaderLen
        buf[u] = ((srcPort shr 8) and 0xFF).toByte()
        buf[u + 1] = (srcPort and 0xFF).toByte()
        buf[u + 2] = ((dstPort shr 8) and 0xFF).toByte()
        buf[u + 3] = (dstPort and 0xFF).toByte()
        buf[u + 4] = ((udpLen shr 8) and 0xFF).toByte()
        buf[u + 5] = (udpLen and 0xFF).toByte()

        System.arraycopy(payload, 0, buf, u + UDP_HEADER_SIZE, payload.size)

        // UDP checksum
        val udpCksum = udpChecksum(buf, ipHeaderLen, udpLen, srcIp, dstIp)
        buf[u + 6] = ((udpCksum shr 8) and 0xFF).toByte()
        buf[u + 7] = (udpCksum and 0xFF).toByte()

        return buf
    }

    fun ipChecksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        var len = length
        while (len > 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
            len -= 2
        }
        if (len > 0) sum += (buf[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.toInt().inv()) and 0xFFFF
    }

    private fun tcpChecksum(buf: ByteArray, tcpOffset: Int, tcpLen: Int, srcIp: Int, dstIp: Int): Int {
        var sum = 0L
        // pseudo header
        sum += ((srcIp shr 16) and 0xFFFF).toLong()
        sum += (srcIp and 0xFFFF).toLong()
        sum += ((dstIp shr 16) and 0xFFFF).toLong()
        sum += (dstIp and 0xFFFF).toLong()
        sum += PROTO_TCP.toLong()
        sum += tcpLen.toLong()
        // TCP segment (with checksum field zeroed)
        var i = tcpOffset
        var len = tcpLen
        while (len > 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
            len -= 2
        }
        if (len > 0) sum += (buf[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.toInt().inv()) and 0xFFFF
    }

    private fun udpChecksum(buf: ByteArray, udpOffset: Int, udpLen: Int, srcIp: Int, dstIp: Int): Int {
        var sum = 0L
        sum += ((srcIp shr 16) and 0xFFFF).toLong()
        sum += (srcIp and 0xFFFF).toLong()
        sum += ((dstIp shr 16) and 0xFFFF).toLong()
        sum += (dstIp and 0xFFFF).toLong()
        sum += PROTO_UDP.toLong()
        sum += udpLen.toLong()
        var i = udpOffset
        var len = udpLen
        while (len > 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
            len -= 2
        }
        if (len > 0) sum += (buf[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        val result = (sum.toInt().inv()) and 0xFFFF
        return if (result == 0) 0xFFFF else result
    }
}
