package com.unbihex.vpn

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileOutputStream

/**
 * Tells the Rust side that an activity of the app came to the front.
 *
 * Swiping the app away destroys its activity while the VPN keeps the process alive.
 * Opening the app again creates a new activity, but Tauri creates windows only at
 * start and reports activity resumes only to existing windows, so the new activity
 * would stay blank. Every resume writes a byte to a pipe; the Rust side reads it and
 * creates the window again when it has none.
 */
object UiSignal : Application.ActivityLifecycleCallbacks {
    private const val TAG = "UnbihexUi"
    private var registered = false
    private var writer: FileOutputStream? = null
    private var reader: ParcelFileDescriptor? = null

    /** Starts watching the app's activities (once per process). */
    @Synchronized
    fun watch(application: Application) {
        if (registered) return
        registered = true
        val pipe = ParcelFileDescriptor.createPipe()
        reader = pipe[0]
        writer = ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])
        application.registerActivityLifecycleCallbacks(this)
    }

    /** The read end for the Rust side, handed out once; the caller owns it. */
    @Synchronized
    fun takeReader(): Int? {
        val r = reader ?: return null
        reader = null
        return r.detachFd()
    }

    override fun onActivityResumed(activity: Activity) {
        try {
            synchronized(this) { writer?.write(1) }
        } catch (e: Exception) {
            Log.w(TAG, "signal: ${e.message}")
        }
    }

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
    override fun onActivityStarted(activity: Activity) {}
    override fun onActivityPaused(activity: Activity) {}
    override fun onActivityStopped(activity: Activity) {}
    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
    override fun onActivityDestroyed(activity: Activity) {}
}
