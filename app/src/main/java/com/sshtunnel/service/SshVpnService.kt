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

                // 2. Start SOCKS5 proxy on the server via exec channel,
                //    then forward a local port to it — only 2 SSH channels total.
                val remoteSocksPort = 18080
                val localSocksPort = 10800
                log("Starting remote SOCKS5 proxy on server port $remoteSocksPort...")

                val socksScript = """
import socket,select,struct,threading,sys,signal
signal.signal(signal.SIGTERM,lambda *a:sys.exit(0))
def h(c):
 try:
  c.settimeout(30);c.recv(256);c.send(b'\x05\x00')
  d=c.recv(256);a=d[3]
  if a==1:addr=socket.inet_ntoa(d[4:8]);p=struct.unpack('!H',d[8:10])[0]
  elif a==3:n=d[4];addr=d[5:5+n].decode();p=struct.unpack('!H',d[5+n:7+n])[0]
  else:c.close();return
  r=socket.create_connection((addr,p),10);r.settimeout(None);c.settimeout(None)
  c.send(b'\x05\x00\x00\x01'+socket.inet_aton(r.getsockname()[0])+struct.pack('!H',r.getsockname()[1]))
  while 1:
   rs,_,_=select.select([c,r],[],[],120)
   if not rs:break
   for s in rs:
    d=s.recv(32768)
    if not d:return
    (r if s is c else c).sendall(d)
 except:pass
 finally:
  try:c.close()
  except:pass
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',int(sys.argv[1])));s.listen(128);print('SOCKS5_READY')
sys.stdout.flush()
while 1:
 c,_=s.accept();threading.Thread(target=h,args=(c,),daemon=True).start()
""".trimIndent()

                // Kill any leftover SOCKS5 from previous run
                try {
                    val killCh = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
                    killCh.setCommand("fuser -k $remoteSocksPort/tcp 2>/dev/null; sleep 0.2")
                    killCh.connect(5000)
                    Thread.sleep(500)
                    killCh.disconnect()
                    log("Cleaned up old SOCKS5 process")
                } catch (_: Exception) {}

                val execCh = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
                execCh.setErrStream(System.err)
                val cmd = "python3 -c ${socksScript.replace("'", "'\\''").let { "'$it'" }} $remoteSocksPort"
                execCh.setCommand(cmd)
                val execIn = execCh.inputStream
                val execErr = execCh.errStream
                execCh.connect(10000)
                log("SOCKS5 exec channel opened, waiting for ready signal...")

                // Wait for "SOCKS5_READY" from the server (with timeout)
                val reader = execIn.bufferedReader()
                var readyLine: String? = null
                val readThread = Thread {
                    readyLine = try { reader.readLine() } catch (_: Exception) { null }
                }
                readThread.start()
                readThread.join(5000)
                if (readyLine != "SOCKS5_READY") {
                    val errMsg = try { String(execErr.readBytes().take(500).toByteArray()) } catch (_: Exception) { "" }
                    throw Exception("SOCKS5 server failed to start: stdout='$readyLine' stderr='$errMsg'")
                }
                log("Remote SOCKS5 proxy ready on server:$remoteSocksPort")

                // Single local port forward → only 1 additional SSH channel
                session.setPortForwardingL(localSocksPort, "127.0.0.1", remoteSocksPort)
                log("Local port forward: 127.0.0.1:$localSocksPort -> server:$remoteSocksPort")
                val socksPort = localSocksPort

                // 3. Setup VPN TUN interface
                log("Setting up VPN TUN interface...")

                val builder = Builder()
                    .setSession("SSH Tunnel VPN")
                    .addAddress("10.0.0.2", 32)
                    .addRoute("0.0.0.0", 1)
                    .addRoute("128.0.0.0", 1)
                    .addDnsServer(profile.dnsServer)
                    .setMtu(1500)
                    .setBlocking(true)

                // Exclude our own app so SOCKS5 traffic bypasses VPN
                try {
                    builder.addDisallowedApplication(packageName)
                    log("Excluded own package from VPN routes")
                } catch (e: Exception) {
                    log("Could not exclude own package", e)
                }

                val fd = builder.establish()
                if (fd == null) {
                    log("VPN establish returned null - permission issue?")
                    throw Exception("VPN establish failed (null fd)")
                }
                vpnFd = fd
                log("VPN TUN interface established, fd=${fd.fd}")

                // 4. Start tunnel engine (routes TUN traffic through SOCKS5)
                log("Starting tunnel engine...")
                val engine = TunnelEngine(
                    tunFdIn = FileInputStream(fd.fileDescriptor),
                    tunFdOut = FileOutputStream(fd.fileDescriptor),
                    socksPort = socksPort,
                    dnsServer = profile.dnsServer
                )
                tunnelEngine = engine
                engine.start()

                currentState = VpnState.CONNECTED
                updateNotification(getString(R.string.notification_connected, profile.name))
                log("=== VPN tunnel fully established ===")

                // Keep alive check with health monitoring
                var lastCheck = System.currentTimeMillis()
                while (!Thread.interrupted() && session.isConnected) {
                    Thread.sleep(2000)
                    val now = System.currentTimeMillis()
                    if (!session.isConnected) {
                        log("!!! SSH session lost connectivity after ${(now - lastCheck)}ms")
                        break
                    }
                    lastCheck = now
                }

                log("SSH session disconnected or thread interrupted, isConnected=${session.isConnected}")
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

        try { sshSession?.delPortForwardingL(10800) } catch (_: Exception) {}
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
