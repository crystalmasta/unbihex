package com.unbihex.vpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class StartArgs {
    var mtu: Int = 1500
    var address: String = "10.199.233.1"
    var prefix: Int = 30
    var dns: String = "10.199.233.2"
    var session: String = "Unbihex"
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
        UnbihexVpnService.onEstablished = { fd, error ->
            if (fd != null) {
                val res = JSObject()
                res.put("fd", fd)
                invoke.resolve(res)
            } else {
                invoke.reject(error ?: "Не удалось запустить VPN")
            }
        }
        val intent = Intent(activity, UnbihexVpnService::class.java).apply {
            action = UnbihexVpnService.ACTION_START
            putExtra(UnbihexVpnService.EXTRA_MTU, args.mtu)
            putExtra(UnbihexVpnService.EXTRA_ADDRESS, args.address)
            putExtra(UnbihexVpnService.EXTRA_PREFIX, args.prefix)
            putExtra(UnbihexVpnService.EXTRA_DNS, args.dns)
            putExtra(UnbihexVpnService.EXTRA_SESSION, args.session)
        }
        try {
            activity.startService(intent)
        } catch (e: Exception) {
            UnbihexVpnService.onEstablished = null
            invoke.reject("Не удалось запустить VPN-сервис: ${e.message}")
        }
    }

    @Command
    fun stop(invoke: Invoke) {
        val intent = Intent(activity, UnbihexVpnService::class.java).apply {
            action = UnbihexVpnService.ACTION_STOP
        }
        try {
            activity.startService(intent)
        } catch (_: Exception) {
            // The service is not running: nothing to stop.
        }
        invoke.resolve()
    }

    @Command
    fun status(invoke: Invoke) {
        val active = UnbihexVpnService.isActive
        val res = JSObject()
        res.put("active", active)
        res.put("state", if (active) "connected" else "disconnected")
        invoke.resolve(res)
    }
}
