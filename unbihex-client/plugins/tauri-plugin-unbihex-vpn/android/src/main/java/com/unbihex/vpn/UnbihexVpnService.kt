package com.unbihex.vpn

import android.app.*
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import android.util.Log
import androidx.annotation.Keep
import org.json.JSONObject
import java.util.concurrent.Executors

object NativeVpn {
    init { System.loadLibrary("unbihex_client_lib") }
    external fun start(dataDir: String, service: UnbihexVpnService, generation: Long, bootstrapDns: String): String?
    external fun stop(generation: Long)
}

class UnbihexVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.unbihex.vpn.START"
        const val ACTION_TILE_START = "com.unbihex.vpn.TILE_START"
        const val ACTION_STOP = "com.unbihex.vpn.STOP"
        const val EXTRA_MTU = "mtu"
        const val EXTRA_ADDRESS = "address"
        const val EXTRA_PREFIX = "prefix"
        const val EXTRA_DNS = "dns"
        const val EXTRA_SESSION = "session"
        const val EXTRA_SERVER = "server"
        const val EXTRA_NOTIFICATION = "notification"
        const val EXTRA_GENERATION = "generation"
        private const val TAG = "UnbihexVpn"
        private const val CHANNEL_ID = "vpn"
        private const val NOTIFICATION_ID = 1
        private val lock = Any()
        private val worker = Executors.newSingleThreadExecutor()
        private val lifecycle = VpnLifecycle()
        private var current: UnbihexVpnService? = null
        @Volatile var isActive = false
        val state: String get() = synchronized(lock) { lifecycle.state }
        private val callbacks = VpnStartCallbacks()

        fun registerCallback(value: Long, callback: (Int?, Int?, Long, String?) -> Unit): Boolean = synchronized(lock) {
            if (!lifecycle.isConnecting(value)) false else {
                callbacks.register(value, callback)
                true
            }
        }

        fun takeCallback(value: Long): ((Int?, Int?, Long, String?) -> Unit)? = synchronized(lock) {
            callbacks.take(value)
        }

        fun refresh(context: android.content.Context) {
            VpnTileService.refresh(context)
        }
        fun reserve(context: android.content.Context): Long? {
            val value = synchronized(lock) { lifecycle.reserve() }
            if (value != null) refresh(context)
            return value
        }

        fun cancel(context: android.content.Context, expected: Long? = null): Boolean {
            var callback: ((Int?, Int?, Long, String?) -> Unit)? = null
            val stopped = synchronized(lock) {
                val old = lifecycle.cancel(expected) ?: return false
                callback = takeCallback(old)
                isActive = false
                current?.closeTunLocked()
                old
            }
            callback?.invoke(null, null, stopped, "Запуск VPN отменён")
            refresh(context)
            worker.execute {
                try {
                    NativeVpn.stop(stopped)
                } catch (e: Throwable) {
                    Log.w(TAG, "native stop failed", e)
                }
            }
            return true
        }

        fun markConnected(context: android.content.Context, value: Long): Boolean {
            val success = synchronized(lock) { lifecycle.connected(value) }
            if (success) refresh(context)
            return success
        }
    }
    private var ownedGeneration: Long? = null
    private var tun: ParcelFileDescriptor? = null
    private var stopSignal: ParcelFileDescriptor? = null

    @Keep fun isGenerationCurrent(value: Long): Boolean = synchronized(lock) {
        lifecycle.isConnecting(value)
    }

    @Keep fun establishFromNative(value: Long, argsJson: String): IntArray {
        val args = JSONObject(argsJson)
        return establish(value, args.optInt("mtu", 1500), args.optString("address", "10.199.233.1"),
            args.optInt("prefix", 30), args.optString("dns", "10.199.233.2"), args.optString("session", "Unbihex"))
    }

    private fun establish(value: Long, mtu: Int, address: String, prefix: Int, dns: String, session: String): IntArray {
        val builder = Builder().setSession(session).setMtu(mtu).addAddress(address, prefix)
            .addRoute("0.0.0.0", 0).addDnsServer(dns)
        try { builder.addAddress("fdb5:2f3c:9a17::1", 126); builder.addRoute("::", 0) }
        catch (e: Exception) { Log.w(TAG, "IPv6 is not available", e) }
        builder.addDisallowedApplication(packageName)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        synchronized(lock) {
            check(lifecycle.isConnecting(value)) { "VPN start cancelled" }
            val pfd = builder.establish() ?: throw IllegalStateException("система не создала VPN-интерфейс")
            var pipe: Array<ParcelFileDescriptor>? = null
            var duplicate: ParcelFileDescriptor? = null
            try {
                pipe = ParcelFileDescriptor.createPipe()
                duplicate = ParcelFileDescriptor.dup(pfd.fileDescriptor)
                closeTunLocked()
                tun = pfd; stopSignal = pipe[1]; isActive = true
                return intArrayOf(duplicate.detachFd(), pipe[0].detachFd())
            } catch (e: Exception) {
                duplicate?.close(); pipe?.forEach { it.close() }; pfd.close(); throw e
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        if (intent.action == ACTION_STOP) {
            val expected = intent.getLongExtra(EXTRA_GENERATION, -1L)
            if (expected >= 0) cancel(this, expected)
            synchronized(lock) {
                if (lifecycle.state == "disconnected") {
                    stopForegroundCompat()
                    stopSelf(startId)
                }
            }
            return START_NOT_STICKY
        }
        if (intent.action != ACTION_START && intent.action != ACTION_TILE_START) return START_NOT_STICKY
        val headless = intent.action == ACTION_TILE_START
        val value = intent.getLongExtra(EXTRA_GENERATION, -1L)
        val callback = if (headless) null else takeCallback(value)
        // Android requires every foreground-service launch to promote promptly, even
        // when its reservation was cancelled before the intent was delivered.
        if (headless) {
            try {
                synchronized(lock) {
                    goForeground("", lifecycle.foregroundConnecting())
                }
            } catch (e: Exception) {
                Log.e(TAG, "foreground service refused", e)
                if (cancel(this, value)) {
                    showFailure("Не удалось запустить VPN")
                    stopSelf(startId)
                }
                return START_NOT_STICKY
            }
        }
        val accepted = synchronized(lock) {
            if (!lifecycle.isConnecting(value)) false else {
                current = this
                ownedGeneration = value
                true
            }
        }
        if (!accepted) {
            callback?.invoke(null, null, value, "Запуск VPN отменён")
            synchronized(lock) {
                if (lifecycle.state == "disconnected") {
                    stopForegroundCompat()
                    stopSelf(startId)
                }
            }
            return START_NOT_STICKY
        }
        if (headless) {
            val dns = org.json.JSONArray(AndroidContext.physicalDns(this)).toString()
            worker.execute {
                val error = try {
                    NativeVpn.start(applicationInfo.dataDir, this, value, dns)
                } catch (e: Throwable) {
                    e.message ?: e.toString()
                }
                Handler(Looper.getMainLooper()).post {
                    if (error == null) {
                        // Recheck and publish together on the main thread so STOP cannot
                        // be followed by a late "connected" notification.
                        synchronized(lock) {
                            if (lifecycle.isConnecting(value) && current === this) {
                                if (markConnected(this, value)) {
                                    try {
                                        goForeground("")
                                    } catch (e: Exception) {
                                        Log.w(TAG, "notification update failed", e)
                                    }
                                }
                            }
                        }
                    } else if (cancel(this, value)) {
                        Log.e(TAG, "VPN start failed: $error")
                        showFailure("Не удалось подключить VPN: $error")
                        stopSelf(startId)
                    }
                }
            }
        } else {
            var fds: IntArray? = null
            try {
                fds = establish(
                    value, intent.getIntExtra(EXTRA_MTU, 1500),
                    intent.getStringExtra(EXTRA_ADDRESS) ?: "10.199.233.1",
                    intent.getIntExtra(EXTRA_PREFIX, 30),
                    intent.getStringExtra(EXTRA_DNS) ?: "10.199.233.2",
                    intent.getStringExtra(EXTRA_SESSION) ?: "Unbihex"
                )
                synchronized(lock) {
                    check(lifecycle.isConnecting(value)) { "VPN start cancelled" }
                    if (intent.getBooleanExtra(EXTRA_NOTIFICATION, true)) {
                        goForeground(intent.getStringExtra(EXTRA_SERVER) ?: "")
                    } else {
                        stopForegroundCompat()
                    }
                }
                if (callback == null) throw IllegalStateException("VPN callback missing")
                callback.invoke(fds[0], fds[1], value, null)
                fds = null
            } catch (e: Exception) {
                fds?.forEach {
                    try { ParcelFileDescriptor.adoptFd(it).close() } catch (_: Exception) { }
                }
                if (cancel(this, value)) stopSelf(startId)
                callback?.invoke(null, null, value, e.message ?: e.toString())
            }
        }
        return START_NOT_STICKY
    }

    private fun showFailure(message: String) {
        Handler(Looper.getMainLooper()).post {
            Toast.makeText(applicationContext, message, Toast.LENGTH_LONG).show()
        }
    }

    /** Shows the "VPN is on" notification and keeps the process alive in the background. */
    private fun goForeground(server: String, connecting: Boolean = false) {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "VPN", NotificationManager.IMPORTANCE_LOW)
            channel.description = "Показывается, пока работает VPN"
            channel.setShowBadge(false)
            nm.createNotificationChannel(channel)
        }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val open = packageManager.getLaunchIntentForPackage(packageName)?.let {
            PendingIntent.getActivity(this, 0, it, flags)
        }
        val stop = PendingIntent.getService(
            this, 1, Intent(this, UnbihexVpnService::class.java).setAction(ACTION_STOP)
                .putExtra(EXTRA_GENERATION, synchronized(lock) { lifecycle.generation }), flags
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this).setPriority(Notification.PRIORITY_LOW)
        }
        builder
            .setSmallIcon(R.drawable.ic_unbihex_vpn)
            .setContentTitle(if (connecting) "Подключение" else "VPN включён")
            .setContentText(if (server.isEmpty()) "Unbihex" else server)
            .setOngoing(true)
            .setShowWhen(false)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(Notification.Action.Builder(null, "Отключить", stop).build())
        if (open != null) {
            builder.setContentIntent(open)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        }
        val notification = builder.build()
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                try {
                    // The type Android documents for VPN apps.
                    startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
                } catch (e: Exception) {
                    Log.w(TAG, "systemExempted refused, using specialUse: ${e.message}")
                    startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
                }
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            throw e
        }
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(Service.STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun closeTunLocked() {
        try { stopSignal?.close() } catch (_: Exception) { }
        stopSignal = null
        try { tun?.close() } catch (_: Exception) { }
        tun = null
    }

    override fun onRevoke() {
        val value = synchronized(lock) { if (current === this) ownedGeneration else null }
        if (value != null) cancel(this, value)
        stopForegroundCompat()
        stopSelf()
    }

    override fun onDestroy() {
        val value = synchronized(lock) {
            // Resources belong to this instance even if another service is current.
            closeTunLocked()
            ownedGeneration
        }
        if (value != null) cancel(this, value)
        synchronized(lock) {
            if (current === this) current = null
        }
        stopForegroundCompat()
        super.onDestroy()
    }
}
