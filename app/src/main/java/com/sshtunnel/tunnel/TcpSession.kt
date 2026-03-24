package com.sshtunnel.tunnel

import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Represents a single TCP connection being proxied through SSH.
 */
data class SessionKey(
    val srcIp: Int,
    val srcPort: Int,
    val dstIp: Int,
    val dstPort: Int
)

class TcpSession(
    val key: SessionKey,
    var state: TcpState = TcpState.SYN_RECEIVED,
    var mySeqNum: Long = (System.nanoTime() and 0xFFFFFFFFL), // our initial seq
    var theirSeqNum: Long = 0,  // client's seq
    var theirAckNum: Long = 0,
    var sshInputStream: InputStream? = null,
    var sshOutputStream: OutputStream? = null,
    val closed: AtomicBoolean = AtomicBoolean(false)
) {
    var channelObject: Any? = null // Socket reference
    val pendingData: MutableList<ByteArray> = mutableListOf()
}

enum class TcpState {
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT,
    CLOSE_WAIT,
    CLOSED
}
