package com.unbihex.vpn

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.json.JSONArray

@InvokeArg
class StartArgs {
    var mtu: Int = 1500
    var address: String = "10.199.233.1"
    var prefix: Int = 30
    var dns: String = "10.199.233.2"
    var session: String = "Unbihex"
    // Server name for the notification.
    var server: String = ""
    // Run in the foreground with a "VPN is on" notification.
    var notification: Boolean = true
    // Used on iOS only; accepted here so both platforms share one argument type.
    var configJson: String = ""
    var serverAddress: String = ""
}

/**
 * Bridge between Rust and [UnbihexVpnService].
 *
 * `start` asks the user for VPN permission (first run only), starts the service and
 * resolves with the TUN file descriptor once the interface is up. The Unbihex engine
 * then runs inside this app process on that descriptor.
 */
@TauriPlugin
class VpnPlugin(private val activity: Activity) : Plugin(activity) {
    private var pendingArgs: StartArgs? = null

    init {
        UiSignal.watch(activity.application)
        // A process killed with the VPN on leaves the tile showing "on": the app's
        // start brings it back to the real state.
        VpnTileService.refresh(activity)
    }

    @Command
    fun start(invoke: Invoke) {
        val args = invoke.parseArgs(StartArgs::class.java)
        val permission = VpnService.prepare(activity)
        if (permission != null) {
            pendingArgs = args
            startActivityForResult(invoke, permission, "onVpnPermission")
        } else {
            launch(invoke, args)
        }
    }

    @ActivityCallback
    fun onVpnPermission(invoke: Invoke, result: ActivityResult) {
        val args = pendingArgs
        pendingArgs = null
        if (result.resultCode == Activity.RESULT_OK && args != null) {
            launch(invoke, args)
        } else {
            invoke.reject("Разрешение на VPN не выдано")
        }
    }

    private fun launch(invoke: Invoke, args: StartArgs) {
        val generation = UnbihexVpnService.reserve(activity.applicationContext)
        if (generation == null) {
            invoke.reject("VPN уже подключён или подключается")
            return
        }
        if (args.notification) {
            askNotificationPermission()
        }
        // Snapshot before establish(): afterwards the default network may be the
        // VPN, whose fake DNS cannot bootstrap the proxy server itself.
        val bootstrapDns = AndroidContext.physicalDns(activity)
        val registered = UnbihexVpnService.registerCallback(generation) { fd, stopFd, generation, error ->
            if (fd != null) {
                val res = JSObject()
                res.put("fd", fd)
                res.put("stopFd", stopFd)
                res.put("generation", generation)
                res.put("bootstrapDns", JSONArray(bootstrapDns))
                invoke.resolve(res)
            } else {
                invoke.reject(error ?: "Не удалось запустить VPN")
            }
        }
        if (!registered) {
            invoke.reject("Запуск VPN отменён")
            return
        }
        val intent = Intent(activity, UnbihexVpnService::class.java).apply {
            action = UnbihexVpnService.ACTION_START
            putExtra(UnbihexVpnService.EXTRA_GENERATION, generation)
            putExtra(UnbihexVpnService.EXTRA_MTU, args.mtu)
            putExtra(UnbihexVpnService.EXTRA_ADDRESS, args.address)
            putExtra(UnbihexVpnService.EXTRA_PREFIX, args.prefix)
            putExtra(UnbihexVpnService.EXTRA_DNS, args.dns)
            putExtra(UnbihexVpnService.EXTRA_SESSION, args.session)
            putExtra(UnbihexVpnService.EXTRA_SERVER, args.server)
            putExtra(UnbihexVpnService.EXTRA_NOTIFICATION, args.notification)
        }
        try {
            // The application context: Tauri keeps handing plugins the first activity,
            // which is gone once the app was swiped away with the VPN on.
            activity.applicationContext.startService(intent)
        } catch (e: Exception) {
            val callback = UnbihexVpnService.takeCallback(generation)
            UnbihexVpnService.cancel(activity.applicationContext, generation)
            callback?.invoke(null, null, generation, "Не удалось запустить VPN-сервис: ${e.message}")
        }
    }

    /**
     * Android 13+: notifications need a runtime permission. Asked on connect while
     * not granted (Android itself stops asking after two refusals), without waiting:
     * if it is refused the VPN still runs in the foreground, only the notification
     * is not shown.
     */
    private fun askNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val permission = Manifest.permission.POST_NOTIFICATIONS
        if (activity.isDestroyed) return
        if (activity.checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {
            try {
                activity.requestPermissions(arrayOf(permission), 0)
            } catch (_: Exception) {
            }
        }
    }

    @InvokeArg
    class StopArgs { var generation: Long? = null }

    @Command
    fun stop(invoke: Invoke) {
        val args = invoke.parseArgs(StopArgs::class.java)
        if (!UnbihexVpnService.cancel(activity.applicationContext, args.generation)) { invoke.resolve(); return }
        val intent = Intent(activity, UnbihexVpnService::class.java).apply {
            action = UnbihexVpnService.ACTION_STOP
            putExtra(UnbihexVpnService.EXTRA_GENERATION, args.generation ?: -1L)
        }
        try {
            // The application context: this activity may be gone already.
            activity.applicationContext.startService(intent)
        } catch (_: Exception) {
            // The service is not running: nothing to stop.
        }
        invoke.resolve()
    }

    @InvokeArg
    class GenerationArgs { var generation: Long = 0 }

    @Command
    fun markConnected(invoke: Invoke) {
        val args = invoke.parseArgs(GenerationArgs::class.java)
        if (UnbihexVpnService.markConnected(activity.applicationContext, args.generation)) invoke.resolve()
        else invoke.reject("запуск VPN отменён")
    }

    /** The read end of [UiSignal]'s pipe, once; the Rust side owns it after this. */
    @Command
    fun uiSignal(invoke: Invoke) {
        val res = JSObject()
        res.put("fd", UiSignal.takeReader())
        invoke.resolve(res)
    }

    @Command
    fun status(invoke: Invoke) {
        // A live TUN also covers the interval before the engine is confirmed.
        val active = UnbihexVpnService.isActive
        val res = JSObject()
        res.put("active", active)
        res.put("state", UnbihexVpnService.state)
        invoke.resolve(res)
    }
}
