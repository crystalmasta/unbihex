package com.unbihex.vpn

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.util.Base64
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import androidx.activity.result.ActivityResult
import androidx.core.content.FileProvider
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.json.JSONArray
import java.io.File

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
    // Which apps use the VPN: "all", "only" (just [apps]) or "except" (all but [apps]).
    var appsMode: String = "all"
    var apps: Array<String> = arrayOf()
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
        NetWatch.start(activity)
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
            putExtra(UnbihexVpnService.EXTRA_APPS_MODE, args.appsMode)
            putExtra(UnbihexVpnService.EXTRA_APPS, args.apps)
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

    /**
     * Every installed package, system ones too (QUERY_ALL_PACKAGES in the
     * manifest makes them visible on Android 11+), Unbihex excluded, each with
     * a small icon.
     */
    @Command
    fun listApps(invoke: Invoke) {
        val context = activity.applicationContext
        Thread {
            try {
                val pm = context.packageManager
                val found = if (Build.VERSION.SDK_INT >= 33) {
                    pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstalledApplications(0)
                }
                val seen = HashSet<String>()
                val apps = JSArray()
                for (app in found) {
                    if (app.packageName == context.packageName || !seen.add(app.packageName)) continue
                    val item = JSObject()
                    item.put("package", app.packageName)
                    item.put("name", app.loadLabel(pm).toString())
                    item.put("system", (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                        (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0)
                    icon(pm, app)?.let { item.put("icon", it) }
                    apps.put(item)
                }
                val res = JSObject()
                res.put("apps", apps)
                invoke.resolve(res)
            } catch (e: Exception) {
                invoke.reject("Не удалось получить список приложений: ${e.message}")
            }
        }.start()
    }

    private fun icon(pm: PackageManager, app: ApplicationInfo): String? = try {
        val size = 48
        val drawable = app.loadIcon(pm)
        val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
        drawable.setBounds(0, 0, size, size)
        drawable.draw(Canvas(bitmap))
        val out = java.io.ByteArrayOutputStream()
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
        bitmap.recycle()
        "data:image/png;base64," + Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
    } catch (_: Exception) {
        null
    }

    /** The tile asks the native side for its label again (another server in use). */
    @Command
    fun refreshTile(invoke: Invoke) {
        VpnTileService.refresh(activity.applicationContext)
        invoke.resolve()
    }

    @InvokeArg
    class ShareArgs {
        var name: String = "unbihex-log.txt"
        var text: String = ""
    }

    /**
     * The text as a .txt file into the share sheet, so it goes to Telegram and the
     * like as a file. It lives in the cache (`share/`, the previous one replaced)
     * and is lent to the chosen app through [UnbihexFileProvider].
     */
    @Command
    fun shareText(invoke: Invoke) {
        val args = invoke.parseArgs(ShareArgs::class.java)
        try {
            val dir = File(activity.cacheDir, "share")
            dir.mkdirs()
            dir.listFiles()?.forEach { it.delete() }
            val name = File(args.name).name.ifBlank { "unbihex-log.txt" }
            val file = File(dir, name)
            file.writeText(args.text)
            val uri = FileProvider.getUriForFile(activity, UnbihexFileProvider.authority(activity), file)
            val send = Intent(Intent.ACTION_SEND)
                .setType("text/plain")
                .putExtra(Intent.EXTRA_STREAM, uri)
                .putExtra(Intent.EXTRA_SUBJECT, name)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            send.clipData = ClipData.newRawUri(name, uri)
            activity.startActivity(Intent.createChooser(send, "Отправить журнал"))
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject("Не удалось поделиться журналом: ${e.message}")
        }
    }

    private fun updatesDir() = File(activity.cacheDir, "updates")

    /** Where the Rust side puts a downloaded update; older files there are removed. */
    @Command
    fun updateDir(invoke: Invoke) {
        val dir = updatesDir()
        dir.mkdirs()
        dir.listFiles()?.forEach { it.delete() }
        val res = JSObject()
        res.put("path", dir.absolutePath)
        invoke.resolve(res)
    }

    @InvokeArg
    class InstallArgs { var path: String = "" }

    /**
     * Opens the system installer for an APK of Unbihex that the Rust side downloaded
     * into [updatesDir] and checked against SHA256SUMS.txt; Android itself refuses an
     * APK signed with another key. Without "Install unknown apps" allowed for
     * Unbihex, its settings page opens and the command says what to do.
     */
    @Command
    fun installApk(invoke: Invoke) {
        val args = invoke.parseArgs(InstallArgs::class.java)
        try {
            val file = File(args.path).canonicalFile
            if (file.parentFile != updatesDir().canonicalFile || !file.isFile || !file.name.endsWith(".apk")) {
                invoke.reject("Файл обновления не найден")
                return
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !activity.packageManager.canRequestPackageInstalls()) {
                try {
                    activity.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        Uri.parse("package:${activity.packageName}")))
                } catch (_: Exception) {
                }
                invoke.reject("Android не разрешает Unbihex устанавливать обновления. В открывшихся настройках " +
                    "включите «Разрешить установку из этого источника», вернитесь и нажмите «Обновить» ещё раз.")
                return
            }
            val uri = FileProvider.getUriForFile(activity, UnbihexFileProvider.authority(activity), file)
            val view = Intent(Intent.ACTION_VIEW)
                .setDataAndType(uri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            activity.startActivity(view)
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject("Не удалось открыть установку: ${e.message}")
        }
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
