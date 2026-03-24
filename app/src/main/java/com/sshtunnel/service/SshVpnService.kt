package com.sshtunnel.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Logger as JSchLogger
import com.jcraft.jsch.Session
import com.sshtunnel.R
import com.sshtunnel.data.AuthMethod
import com.sshtunnel.data.ServerProfile
import com.sshtunnel.tunnel.TunnelEngine
import com.sshtunnel.ui.MainActivity
import net.i2p.crypto.eddsa.EdDSASecurityProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.Security
import java.util.Properties
import java.util.concurrent.atomic.AtomicReference

class SshVpnService : VpnService() {

    companion object {
        private const val TAG = "SshVpnService"
        private const val CHANNEL_ID = "ssh_tunnel_vpn"
        private const val NOTIFICATION_ID = 1
        const val ACTION_START = "com.sshtunnel.START"
        const val ACTION_STOP = "com.sshtunnel.STOP"
        const val EXTRA_PROFILE_JSON = "profile_json"

        var stateListener: ((VpnState) -> Unit)? = null
        var currentState: VpnState = VpnState.DISCONNECTED
            private set(value) {
                field = value
                stateListener?.invoke(value)
            }

        /** Ring buffer of recent log lines, readable from UI */
        val logBuffer = LogBuffer(500)
    }

    private var vpnFd: ParcelFileDescriptor? = null
    private var sshSession: Session? = null
    private var tunnelEngine: TunnelEngine? = null
    private val workerThread = AtomicReference<Thread?>()

    override fun onCreate() {
        super.onCreate()
        registerEdDSAProvider()
        createNotificationChannel()
        installJSchLogger()
    }

    /** Register crypto providers for ed25519 + curve25519 support */
    private fun registerEdDSAProvider() {
        if (Security.getProvider(EdDSASecurityProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(EdDSASecurityProvider(), 1)
            Log.i(TAG, "EdDSA security provider registered")
        }
        // Replace Android's crippled BC with full BouncyCastle for curve25519/chacha20
        Security.removeProvider("BC")
        Security.insertProviderAt(BouncyCastleProvider(), 2)
        Log.i(TAG, "BouncyCastle provider registered")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val json = intent.getStringExtra(EXTRA_PROFILE_JSON) ?: return START_NOT_STICKY
                val profile = com.google.gson.Gson().fromJson(json, ServerProfile::class.java)
                startVpn(profile)
            }
            ACTION_STOP -> stopVpn()
        }
        return START_STICKY
    }

    /** Install a JSch logger that forwards everything to Android logcat + our ring buffer */
    private fun installJSchLogger() {
        JSch.setLogger(object : JSchLogger {
            override fun isEnabled(level: Int): Boolean = true

            override fun log(level: Int, message: String?) {
                val msg = message ?: return
                val priority = when (level) {
                    JSchLogger.DEBUG -> Log.DEBUG
                    JSchLogger.INFO  -> Log.INFO
                    JSchLogger.WARN  -> Log.WARN
                    JSchLogger.ERROR -> Log.ERROR
                    JSchLogger.FATAL -> Log.ERROR
                    else -> Log.VERBOSE
                }
                val tag = "JSch"
                Log.println(priority, tag, msg)
                logBuffer.append("[$tag] $msg")
            }
        })
    }

    private fun log(msg: String, e: Throwable? = null) {
        if (e != null) {
            Log.e(TAG, msg, e)
            logBuffer.append("[ERROR] $msg: ${e.javaClass.simpleName}: ${e.message}")
            // print full stacktrace into log buffer
            val sw = java.io.StringWriter()
            e.printStackTrace(java.io.PrintWriter(sw))
            sw.toString().lines().forEach { logBuffer.append("  $it") }
        } else {
            Log.i(TAG, msg)
            logBuffer.append("[INFO] $msg")
        }
    }

    private fun startVpn(profile: ServerProfile) {
        if (currentState == VpnState.CONNECTED || currentState == VpnState.CONNECTING) return

        logBuffer.clear()
        currentState = VpnState.CONNECTING
        startForeground(NOTIFICATION_ID, buildNotification("Connecting to ${profile.name}..."))

        val thread = Thread {
            try {
                log("=== Starting SSH connection ===")
                log("Host: ${profile.host}:${profile.port}")
                log("User: ${profile.username}")
                log("Auth method: ${profile.authMethod}")
                if (profile.authMethod == AuthMethod.KEY) {
                    val keyPreview = profile.privateKey.take(40).replace("\n", "\\n")
                    log("Key starts with: $keyPreview...")
                    log("Key length: ${profile.privateKey.length} chars")
                    log("Has passphrase: ${profile.keyPassphrase.isNotBlank()}")
                }
                log("DNS: ${profile.dnsServer}")

                // 1. Establish SSH connection
                val jsch = JSch()

                if (profile.authMethod == AuthMethod.KEY && profile.privateKey.isNotBlank()) {
                    log("Adding SSH identity from private key...")
                    try {
                        val keyBytes = profile.privateKey.toByteArray(Charsets.UTF_8)
                        val passphrase = if (profile.keyPassphrase.isNotBlank())
                            profile.keyPassphrase.toByteArray(Charsets.UTF_8) else null
                        jsch.addIdentity("key", keyBytes, null, passphrase)
                        log("Identity added successfully")
                    } catch (e: Exception) {
                        log("Failed to add identity", e)
                        throw e
                    }
                }

                log("Creating SSH session...")
                val session = jsch.getSession(profile.username, profile.host, profile.port)

                if (profile.authMethod == AuthMethod.PASSWORD) {
                    log("Setting password authentication (password length: ${profile.password.length})")
                    session.setPassword(profile.password)
                }

                val config = Properties()
                config["StrictHostKeyChecking"] = "no"
                val authMethods = when (profile.authMethod) {
                    AuthMethod.PASSWORD -> "password,keyboard-interactive"
                    AuthMethod.KEY -> "publickey"
                }
                config["PreferredAuthentications"] = authMethods
                log("PreferredAuthentications: $authMethods")
                session.setConfig(config)
                session.setServerAliveInterval(15000)
                session.setServerAliveCountMax(3)

                log("Setting up protected socket factory...")
                session.setSocketFactory(ProtectedSocketFactory(this@SshVpnService))

                log("Connecting to SSH server (timeout: 15s)...")
                session.connect(15000)
                sshSession = session

                log("=== SSH connected successfully ===")
                log("Server version: ${session.serverVersion}")
                log("Client version: ${session.clientVersion}")

                // --- DIAGNOSTIC: test direct-tcpip BEFORE VPN ---
                log("=== DIAG: testing direct-tcpip BEFORE VPN ===")
                try {
                    val testCh = session.openChannel("direct-tcpip") as com.jcraft.jsch.ChannelDirectTCPIP
                    testCh.setHost("8.8.8.8")
                    testCh.setPort(53)
                    testCh.connect(5000)
                    log("DIAG: direct-tcpip BEFORE VPN -> SUCCESS")
                    testCh.disconnect()
                } catch (e: Exception) {
                    log("DIAG: direct-tcpip BEFORE VPN -> FAILED", e)
                }

                // Also test exec channel
                log("=== DIAG: testing exec channel ===")
                try {
                    val execCh = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
                    execCh.setCommand("echo tunnel_test_ok")
                    execCh.inputStream = null
                    val execIn = execCh.inputStream
                    execCh.connect(5000)
                    val result = execIn.bufferedReader().readText().trim()
                    log("DIAG: exec channel -> SUCCESS, output='$result'")
                    execCh.disconnect()
                } catch (e: Exception) {
                    log("DIAG: exec channel -> FAILED", e)
                }

                // 2. Setup VPN TUN interface
                log("Setting up VPN TUN interface...")
                val builder = Builder()
                    .setSession("SSH Tunnel VPN")
                    .addAddress("10.0.0.2", 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer(profile.dnsServer)
                    .setMtu(1500)
                    .setBlocking(true)

                val fd = builder.establish()
                if (fd == null) {
                    log("VPN establish returned null - permission issue?")
                    throw Exception("VPN establish failed (null fd)")
                }
                vpnFd = fd
                log("VPN TUN interface established, fd=${fd.fd}")

                // --- DIAGNOSTIC: test direct-tcpip AFTER VPN ---
                log("=== DIAG: testing direct-tcpip AFTER VPN ===")
                try {
                    val testCh2 = session.openChannel("direct-tcpip") as com.jcraft.jsch.ChannelDirectTCPIP
                    testCh2.setHost("8.8.8.8")
                    testCh2.setPort(53)
                    testCh2.connect(5000)
                    log("DIAG: direct-tcpip AFTER VPN -> SUCCESS")
                    testCh2.disconnect()
                } catch (e: Exception) {
                    log("DIAG: direct-tcpip AFTER VPN -> FAILED", e)
                }

                // 3. Start tunnel engine
                log("Starting tunnel engine...")
                val engine = TunnelEngine(
                    tunFdIn = FileInputStream(fd.fileDescriptor),
                    tunFdOut = FileOutputStream(fd.fileDescriptor),
                    sshSession = session,
                    dnsServer = profile.dnsServer,
                    protectSocket = { socketFd -> protect(socketFd) }
                )
                tunnelEngine = engine
                engine.start()

                currentState = VpnState.CONNECTED
                updateNotification(getString(R.string.notification_connected, profile.name))
                log("=== VPN tunnel fully established ===")

                // Keep alive check
                while (!Thread.interrupted() && session.isConnected) {
                    Thread.sleep(5000)
                }

                log("SSH session disconnected or thread interrupted")
                stopVpn()

            } catch (e: Exception) {
                log("=== VPN start FAILED ===", e)
                currentState = VpnState.ERROR(e.message ?: "Unknown error")
                stopVpn()
            }
        }
        thread.name = "SshVpnWorker"
        workerThread.set(thread)
        thread.start()
    }

    private fun stopVpn() {
        log("Stopping VPN...")
        tunnelEngine?.stop()
        tunnelEngine = null

        try { sshSession?.disconnect() } catch (_: Exception) {}
        sshSession = null

        try { vpnFd?.close() } catch (_: Exception) {}
        vpnFd = null

        workerThread.getAndSet(null)?.interrupt()

        if (currentState !is VpnState.ERROR) {
            currentState = VpnState.DISCONNECTED
        }

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        log("VPN revoked by system")
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel),
            NotificationManager.IMPORTANCE_LOW
        )
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }
}

sealed class VpnState {
    object DISCONNECTED : VpnState()
    object CONNECTING : VpnState()
    object CONNECTED : VpnState()
    data class ERROR(val message: String) : VpnState()
}

/**
 * Thread-safe ring buffer for log lines. Keeps the last [capacity] lines.
 */
class LogBuffer(private val capacity: Int) {
    private val lines = ArrayDeque<String>()
    var onNewLine: ((String) -> Unit)? = null

    @Synchronized
    fun append(line: String) {
        val stamped = "${java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.US).format(java.util.Date())} $line"
        lines.addLast(stamped)
        while (lines.size > capacity) lines.removeFirst()
        onNewLine?.invoke(stamped)
    }

    @Synchronized
    fun getAll(): List<String> = lines.toList()

    @Synchronized
    fun clear() = lines.clear()
}
