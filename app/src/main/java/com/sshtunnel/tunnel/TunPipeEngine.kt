package com.sshtunnel.tunnel

import android.util.Log
import com.sshtunnel.service.SshVpnService
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Simple packet-pipe engine for SSH TUN mode (ssh -w analog).
 * Reads IP packets from Android TUN, sends them length-prefixed to the SSH channel,
 * and vice versa. No TCP state machine, no SOCKS5 — just raw IP packet forwarding.
 */
class TunPipeEngine(
    private val tunFdIn: FileInputStream,
    private val tunFdOut: FileOutputStream,
    private val sshIn: InputStream,
    private val sshOut: OutputStream
) {
    companion object {
        private const val TAG = "TunPipeEngine"
        private const val MTU = 1500
    }

    private val running = AtomicBoolean(false)
    private val logBuffer get() = SshVpnService.logBuffer

    private fun log(msg: String, e: Throwable? = null) {
        if (e != null) {
            Log.e(TAG, msg, e)
            logBuffer.append("[TunPipe/ERR] $msg: ${e.javaClass.simpleName}: ${e.message}")
        } else {
            Log.i(TAG, msg)
            logBuffer.append("[TunPipe] $msg")
        }
    }

    fun start() {
        running.set(true)
        log("TunPipe engine started")
        Thread({ tunToSsh() }, "TunPipe-t2s").start()
        Thread({ sshToTun() }, "TunPipe-s2t").start()
    }

    fun stop() {
        running.set(false)
        log("TunPipe engine stopping")
    }

    /** Read IP packets from Android TUN → send [2-byte len][packet] to SSH */
    private fun tunToSsh() {
        val buf = ByteArray(MTU)
        try {
            while (running.get()) {
                val len = tunFdIn.read(buf)
                if (len <= 0) continue
                synchronized(sshOut) {
                    sshOut.write(byteArrayOf(
                        ((len shr 8) and 0xFF).toByte(),
                        (len and 0xFF).toByte()
                    ))
                    sshOut.write(buf, 0, len)
                    sshOut.flush()
                }
            }
        } catch (e: IOException) {
            if (running.get()) log("TUN→SSH error", e)
        }
    }

    /** Read [2-byte len][packet] from SSH → write IP packets to Android TUN */
    private fun sshToTun() {
        val hdr = ByteArray(2)
        try {
            while (running.get()) {
                readFully(sshIn, hdr)
                val pktLen = ((hdr[0].toInt() and 0xFF) shl 8) or (hdr[1].toInt() and 0xFF)
                if (pktLen <= 0 || pktLen > 65535) continue
                val pkt = ByteArray(pktLen)
                readFully(sshIn, pkt)
                tunFdOut.write(pkt)
                tunFdOut.flush()
            }
        } catch (e: IOException) {
            if (running.get()) log("SSH→TUN error", e)
        }
    }

    private fun readFully(inp: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = inp.read(buf, off, buf.size - off)
            if (n <= 0) throw IOException("EOF")
            off += n
        }
    }
}
