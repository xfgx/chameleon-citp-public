package com.chameleonvpn.app

import android.content.Context
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

object AppLog {
    private val io = Executors.newSingleThreadExecutor()
    private val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
    @Volatile private var file: File? = null
    @Volatile private var verbose = true

    fun init(ctx: Context) {
        file = File(ctx.filesDir, "chameleon.log")
        try {
            mobilecore.Mobilecore.setLogPath(file!!.absolutePath)
        } catch (_: Throwable) {}
        w("APP", "logger ready, file=${file!!.absolutePath}")
    }

    fun setVerbose(v: Boolean) { verbose = v }

    fun d(tag: String, msg: String) { if (verbose) w(tag, msg) }
    fun i(tag: String, msg: String) { w(tag, msg) }
    fun e(tag: String, msg: String, t: Throwable? = null) {
        val extra = t?.let { "\n" + stack(it) }.orEmpty()
        w(tag, "ERROR $msg$extra")
    }

    fun readTail(maxChars: Int = 80_000): String {
        return try {
            val f = file ?: return ""
            if (!f.exists()) return ""
            val text = f.readText()
            if (text.length <= maxChars) text else text.substring(text.length - maxChars)
        } catch (t: Throwable) { "log read failed: ${t.message}" }
    }

    fun clear() {
        try { file?.writeText("") } catch (_: Throwable) {}
        w("APP", "log cleared")
    }

    fun file(): File? = file

    private fun w(tag: String, msg: String) {
        val line = "${fmt.format(Date())}  [$tag] $msg\n"
        android.util.Log.i("Chameleon/$tag", msg)
        io.execute {
            try { file?.appendText(line) } catch (_: Throwable) {}
        }
    }

    fun stack(t: Throwable): String {
        val sw = StringWriter()
        t.printStackTrace(PrintWriter(sw))
        return sw.toString()
    }
}
