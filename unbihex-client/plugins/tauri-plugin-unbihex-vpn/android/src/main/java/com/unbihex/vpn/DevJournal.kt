package com.unbihex.vpn

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Uri
import android.os.Build
import android.provider.DocumentsContract
import android.system.OsConstants
import app.tauri.annotation.InvokeArg
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress

/** One connection whose owning app is asked for (the journal's `OwnerQuery`). */
@InvokeArg
class OwnerItem {
    var udp: Boolean = false
    var src: String = ""
    var dst: String? = null
}

/**
 * Developer mode: which app owns a connection, and connection reports copied
 * into a folder chosen through the Storage Access Framework.
 */
object DevJournal {
    private const val PREFIX = "unbihex-report-"
    private const val EXT = ".jsonl"

    /** `1.2.3.4:443` or `[2001:db8::1]:443` → an address; only literals, no DNS. */
    private fun parse(s: String?): InetSocketAddress? {
        if (s == null) return null
        val i = s.lastIndexOf(':')
        if (i <= 0) return null
        val host = s.substring(0, i).removePrefix("[").removeSuffix("]")
        val port = s.substring(i + 1).toIntOrNull() ?: return null
        if (!host.all { it.isDigit() || it == '.' || it == ':' || it in 'a'..'f' || it in 'A'..'F' }) return null
        return try {
            InetSocketAddress(InetAddress.getByName(host), port)
        } catch (e: Exception) {
            null
        }
    }

    /** Below Android 10: local port → uid from `/proc/net` (later versions hide it). */
    private fun procUids(): Map<Pair<Boolean, Int>, Int> {
        val out = HashMap<Pair<Boolean, Int>, Int>()
        for ((file, udp) in listOf("tcp" to false, "tcp6" to false, "udp" to true, "udp6" to true)) {
            try {
                File("/proc/net/$file").readLines().drop(1).forEach { line ->
                    val cols = line.trim().split(Regex("\\s+"))
                    val port = cols.getOrNull(1)?.substringAfterLast(':')?.toIntOrNull(16)
                    val uid = cols.getOrNull(7)?.toIntOrNull()
                    if (port != null && uid != null) out[udp to port] = uid
                }
            } catch (e: Exception) {
            }
        }
        return out
    }

    private fun label(pm: PackageManager, uid: Int): String? {
        when (uid) {
            0 -> return "root"
            1000 -> return "Android (system)"
        }
        val pkg = pm.getPackagesForUid(uid)?.firstOrNull() ?: return pm.getNameForUid(uid)
        return try {
            val name = pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
            if (name == pkg) pkg else "$name ($pkg)"
        } catch (e: Exception) {
            pkg
        }
    }

    /** One app name (or null) per item. */
    fun owners(context: Context, items: Array<OwnerItem>): JSONArray {
        val pm = context.packageManager
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val proc = if (Build.VERSION.SDK_INT < 29) procUids() else null
        val names = HashMap<Int, String?>()
        val out = JSONArray()
        for (item in items) {
            val uid = try {
                if (Build.VERSION.SDK_INT >= 29) {
                    val src = parse(item.src)
                    val dst = parse(item.dst)
                    val proto = if (item.udp) OsConstants.IPPROTO_UDP else OsConstants.IPPROTO_TCP
                    if (src == null || dst == null || cm == null) -1 else cm.getConnectionOwnerUid(proto, src, dst)
                } else {
                    val port = parse(item.src)?.port
                    if (port == null) -1 else proc?.get(item.udp to port) ?: -1
                }
            } catch (e: Exception) {
                -1
            }
            val name = if (uid < 0) null else names.getOrPut(uid) { label(pm, uid) }
            out.put(name ?: JSONObject.NULL)
        }
        return out
    }

    /**
     * Copies [path] into the tree [treeUri] under its own name, then deletes the
     * tree's oldest `unbihex-report-*.jsonl` beyond [keep]; other files stay.
     */
    fun export(context: Context, treeUri: String, path: String, keep: Int) {
        val cr = context.contentResolver
        val tree = Uri.parse(treeUri)
        val treeId = DocumentsContract.getTreeDocumentId(tree)
        val parent = DocumentsContract.buildDocumentUriUsingTree(tree, treeId)
        val file = File(path)
        val doc = DocumentsContract.createDocument(cr, parent, "application/octet-stream", file.name)
            ?: throw IllegalStateException("папка недоступна")
        cr.openOutputStream(doc)?.use { out -> file.inputStream().use { it.copyTo(out) } }
            ?: throw IllegalStateException("файл не открылся")
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, treeId)
        val reports = ArrayList<Pair<String, String>>()
        cr.query(
            children,
            arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME),
            null, null, null,
        )?.use { c ->
            while (c.moveToNext()) {
                val id = c.getString(0) ?: continue
                val name = c.getString(1) ?: continue
                if (name.startsWith(PREFIX) && name.endsWith(EXT)) reports.add(name to id)
            }
        }
        reports.sortBy { it.first }
        val extra = reports.size - keep.coerceIn(1, 100)
        for (i in 0 until extra) {
            try {
                DocumentsContract.deleteDocument(cr, DocumentsContract.buildDocumentUriUsingTree(tree, reports[i].second))
            } catch (e: Exception) {
            }
        }
    }
}
