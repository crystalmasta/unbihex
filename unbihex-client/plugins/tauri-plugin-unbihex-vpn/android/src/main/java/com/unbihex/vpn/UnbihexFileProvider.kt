package com.unbihex.vpn

import androidx.core.content.FileProvider

/**
 * content:// links to files in the cache (`res/xml/unbihex_files.xml`) for other apps:
 * its own class, so its manifest entry never merges with the app's FileProvider.
 */
class UnbihexFileProvider : FileProvider() {
    companion object {
        fun authority(context: android.content.Context) = "${context.packageName}.unbihex.files"
    }
}
