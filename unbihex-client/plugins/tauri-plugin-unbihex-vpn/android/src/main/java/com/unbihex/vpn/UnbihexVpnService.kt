package com.unbihex.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Owns the TUN interface. The descriptor stays open here; the engine works on a
 * dup() of it, so closing this one (stop or revoke) plus stopping the engine tears
 * the interface down.
 *
 * The app's own package is excluded from the VPN, which keeps the engine's sockets
 * (to the proxy server, DNS and direct sites) out of the tunnel without protect().
 *
 * With the notification on, the service runs in the foreground: Android then keeps
 * the app process (and the engine in it) alive when the app is swiped away. The
 * notification's "Отключить" stops the VPN without opening the app.
 *
 * Every start hands the engine the read end of a pipe whose write end lives here.
 * Closing it on stop, revoke or "Отключить" is how the engine learns that the VPN
 * is gone, also while the app has no window.
 */
class UnbihexVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.unbihex.vpn.START"
        const val ACTION_STOP = "com.unbihex.vpn.STOP"
        const val EXTRA_MTU = "mtu"
        const val EXTRA_ADDRESS = "address"
        const val EXTRA_PREFIX = "prefix"
        const val EXTRA_DNS = "dns"
        const val EXTRA_SESSION = "session"
        const val EXTRA_SERVER = "server"
        const val EXTRA_NOTIFICATION = "notification"
        private const val TAG = "UnbihexVpn"
        private const val CHANNEL_ID = "vpn"
        private const val NOTIFICATION_ID = 1

        /** True while the interface is up. Read by the plugin's `status`. */
        @Volatile
        var isActive: Boolean = false

        /** Called once with (fd, stopFd, null) or (null, null, error) after a start request. */
        @Volatile
        var onEstablished: ((Int?, Int?, String?) -> Unit)? = null
    }

    private var tun: ParcelFileDescriptor? = null
    /** Write end of the stop pipe; the engine holds the read end. */
    private var stopSignal: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null || intent.action == ACTION_STOP) {
            // A null intent is a restart after the process died: the engine is gone too.
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        val callback = onEstablished
        onEstablished = null
        try {
            closeTun()
            val builder = Builder()
                .setSession(intent.getStringExtra(EXTRA_SESSION) ?: "Unbihex")
                .setMtu(intent.getIntExtra(EXTRA_MTU, 1500))
                .addAddress(
                    intent.getStringExtra(EXTRA_ADDRESS) ?: "10.199.233.1",
                    intent.getIntExtra(EXTRA_PREFIX, 30)
                )
                .addRoute("0.0.0.0", 0)
                .addDnsServer(intent.getStringExtra(EXTRA_DNS) ?: "10.199.233.2")
            // Route IPv6 into the tunnel too, otherwise it would leak around the VPN.
            try {
                builder.addAddress("fdb5:2f3c:9a17::1", 126)
                builder.addRoute("::", 0)
            } catch (e: Exception) {
                Log.w(TAG, "IPv6 is not available: ${e.message}")
            }
            builder.addDisallowedApplication(packageName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }
            val pfd = builder.establish()
                ?: throw IllegalStateException("система не создала VPN-интерфейс (разрешение отозвано?)")
            tun = pfd
            val pipe = ParcelFileDescriptor.createPipe()
            stopSignal = pipe[1]
            isActive = true
            if (intent.getBooleanExtra(EXTRA_NOTIFICATION, true)) {
                goForeground(intent.getStringExtra(EXTRA_SERVER) ?: "")
            } else {
                stopForegroundCompat()
            }
            callback?.invoke(pfd.fd, pipe[0].detachFd(), null)
        } catch (e: Exception) {
            Log.e(TAG, "establish failed", e)
            shutdown()
            callback?.invoke(null, null, e.message ?: e.toString())
        }
        return START_NOT_STICKY
    }

    /** Shows the "VPN is on" notification and keeps the process alive in the background. */
    private fun goForeground(server: String) {
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
            this, 1, Intent(this, UnbihexVpnService::class.java).setAction(ACTION_STOP), flags
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this).setPriority(Notification.PRIORITY_LOW)
        }
        builder
            .setSmallIcon(R.drawable.ic_unbihex_vpn)
            .setContentTitle("VPN включён")
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
            // The VPN still works; it is just not protected from being closed in the background.
            Log.e(TAG, "foreground service refused", e)
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

    private fun closeTun() {
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
        // EOF on the engine's end: it stops and drops its copy of the TUN descriptor.
        try {
            stopSignal?.close()
        } catch (_: Exception) {
        }
        stopSignal = null
    }

    private fun shutdown() {
        isActive = false
        closeTun()
        stopForegroundCompat()
    }

    override fun onRevoke() {
        // Another VPN took over or the user switched us off in Settings.
        shutdown()
        stopSelf()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }
}
