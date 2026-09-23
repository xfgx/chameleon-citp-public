package com.chameleonvpn.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.progressindicator.CircularProgressIndicator
import com.google.android.material.switchmaterial.SwitchMaterial
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.google.android.material.textview.MaterialTextView
import mobilecore.Mobilecore
import java.util.concurrent.atomic.AtomicBoolean

data class ServerProfile(
    val id: String,
    val name: String,
    val mode: String,
    val addr: String,
    val pubkey: String = "",
    val subtitle: String = ""
)

class MainActivity : Activity() {
    private val prefs by lazy { getSharedPreferences("cham", Context.MODE_PRIVATE) }
    private val handler = Handler(Looper.getMainLooper())
    private val connecting = AtomicBoolean(false)

    private lateinit var pageHost: FrameLayout
    private lateinit var nav: LinearLayout
    private var homeStatus: MaterialTextView? = null
    private var homeServer: MaterialTextView? = null
    private var homeMode: MaterialTextView? = null
    private var homeStats: MaterialTextView? = null
    private var homeRx: MaterialTextView? = null
    private var powerButton: MaterialButton? = null
    private var homeProgress: CircularProgressIndicator? = null
    private var logView: MaterialTextView? = null
    private var logScroll: ScrollView? = null

    private var clientKey = ""
    private var prevUp = 0L
    private var prevDown = 0L
    private var prevT = 0L
    private var lastRunning = false
    private var activeTab = TAB_HOME
    private var destroyed = false

    private val cBg = Color.parseColor("#0B1220")
    private val cSurface = Color.parseColor("#121A2B")
    private val cSurface2 = Color.parseColor("#1A2438")
    private val cAccent = Color.parseColor("#3DDC97")
    private val cAccentDim = Color.parseColor("#16382C")
    private val cCitp = Color.parseColor("#6EA8FE")
    private val cText = Color.parseColor("#F4F7FB")
    private val cMuted = Color.parseColor("#8B9BB4")
    private val cDanger = Color.parseColor("#FF6B7A")

    companion object {
        private const val VPN_REQUEST = 100
        private const val TAB_HOME = 1
        private const val TAB_SERVERS = 2
        private const val TAB_LOGS = 3
        private const val TAB_SETTINGS = 4
        const val CITP_PUB = "LaK1-DXOOO0ABWI2DqNkZpeNtmAHiCjJ7OiQHTR8OXY"
    }

    private fun presets(): List<ServerProfile> = listOf(
        ServerProfile(
            id = "ks-ru",
            name = "KS · RU Exit",
            mode = "ks",
            addr = "192.0.2.10:51820",
            subtitle = "Keystream TUN · зарубежный выход через каскад"
        ),
        ServerProfile(
            id = "citp-ru",
            name = "CITP · RU Entry",
            mode = "citp",
            addr = "192.0.2.10:9443",
            pubkey = CITP_PUB,
            subtitle = "Intent-транспорт · каскад на Myserv"
        )
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AppLog.init(this)
        installCrashLogger()
        window.statusBarColor = cBg
        window.navigationBarColor = cBg
        ensureClientKey()
        seedPresets()
        buildShell()
        showTab(TAB_HOME)
        tick()
        AppLog.i("UI", "MainActivity started")
    }

    private fun installCrashLogger() {
        val fallback = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            AppLog.e("CRASH", thread.name, error)
            fallback?.uncaughtException(thread, error)
                ?: android.os.Process.killProcess(android.os.Process.myPid())
        }
    }

    private fun ensureClientKey() {
        var key = prefs.getString("client_priv", "").orEmpty()
        if (key.isEmpty()) {
            key = try { Mobilecore.genClientKey() } catch (_: Throwable) { "" }
            if (key.isEmpty()) {
                AppLog.e("UI", "genClientKey empty")
            } else {
                prefs.edit().putString("client_priv", key).apply()
                AppLog.i("UI", "device key generated")
            }
        }
        clientKey = key
        if (!prefs.contains("russian_bypass")) prefs.edit().putBoolean("russian_bypass", true).apply()
        if (!prefs.contains("bypass_lan")) prefs.edit().putBoolean("bypass_lan", true).apply()
        if (!prefs.contains("dns")) prefs.edit().putString("dns", "8.8.8.8").apply()
        if (!prefs.contains("mtu_ks")) prefs.edit().putInt("mtu_ks", 1300).apply()
        if (!prefs.contains("mtu_citp")) prefs.edit().putInt("mtu_citp", 1500).apply()
        if (!prefs.contains("verbose")) prefs.edit().putBoolean("verbose", true).apply()
        AppLog.setVerbose(prefs.getBoolean("verbose", true))
    }

    private fun seedPresets() {
        val selected = prefs.getString("selected_id", "")
        if (selected.isNullOrEmpty()) {
            val ks = presets().first { it.mode == "ks" }
            prefs.edit()
                .putString("selected_id", ks.id)
                .putString("mode", ks.mode)
                .putString("addr", ks.addr)
                .putString("pubkey", ks.pubkey)
                .apply()
        }
    }

    private fun selected(): ServerProfile {
        val id = prefs.getString("selected_id", "ks-ru")
        return presets().firstOrNull { it.id == id } ?: presets().first()
    }

    private fun buildShell() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(cBg)
        }
        pageHost = FrameLayout(this)
        nav = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(cSurface)
            setPadding(dp(8), dp(8), dp(8), dp(10))
            addView(navBtn("Home", TAB_HOME))
            addView(navBtn("Servers", TAB_SERVERS))
            addView(navBtn("Logs", TAB_LOGS))
            addView(navBtn("Settings", TAB_SETTINGS))
        }
        root.addView(pageHost, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        root.addView(nav, MATCH_PARENT, WRAP_CONTENT)
        setContentView(root)
    }

    private fun navBtn(label: String, tab: Int) = MaterialButton(this).apply {
        text = label
        isAllCaps = false
        textSize = 11f
        setTextColor(if (activeTab == tab) cAccent else cMuted)
        setBackgroundColor(Color.TRANSPARENT)
        cornerRadius = dp(10)
        layoutParams = LinearLayout.LayoutParams(0, dp(44), 1f)
        setOnClickListener { showTab(tab); refreshNav() }
    }

    private fun refreshNav() {
        for (i in 0 until nav.childCount) {
            val b = nav.getChildAt(i) as MaterialButton
            val tab = i + 1
            b.setTextColor(if (activeTab == tab) cAccent else cMuted)
        }
    }

    private fun showTab(tab: Int) {
        activeTab = tab
        pageHost.removeAllViews()
        homeStatus = null; homeServer = null; homeMode = null; homeStats = null
        homeRx = null; powerButton = null; homeProgress = null; logView = null; logScroll = null
        pageHost.addView(when (tab) {
            TAB_SERVERS -> buildServersPage()
            TAB_LOGS -> buildLogsPage()
            TAB_SETTINGS -> buildSettingsPage()
            else -> buildHomePage()
        }, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        refreshNav()
        updateUi(safeRunning())
    }

    private fun buildHomePage(): View {
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(20), dp(24), dp(20), dp(16))
        }
        val brand = text("CHAMELEON", 13f, cMuted, true).apply {
            letterSpacing = 0.28f; gravity = Gravity.CENTER
        }
        homeMode = text(modeLabel(selected().mode), 12f, if (selected().mode == "ks") cAccent else cCitp, true).apply {
            gravity = Gravity.CENTER; setPadding(0, dp(6), 0, 0)
        }
        homeStatus = text("Готов", 22f, cText, true).apply { gravity = Gravity.CENTER }
        homeServer = text(selected().name, 13f, cMuted, false).apply { gravity = Gravity.CENTER }
        homeProgress = CircularProgressIndicator(this).apply {
            visibility = View.GONE
            setIndicatorColor(cAccent)
            setTrackColor(cSurface2)
            indicatorSize = dp(196)
            trackThickness = dp(3)
        }
        powerButton = MaterialButton(this).apply {
            text = "CONNECT"
            textSize = 16f
            isAllCaps = true
            setTextColor(cBg)
            setBackgroundColor(cAccent)
            cornerRadius = dp(96)
            elevation = 8f
            setOnClickListener { onPower() }
        }
        val power = FrameLayout(this).apply {
            addView(homeProgress, FrameLayout.LayoutParams(dp(208), dp(208), Gravity.CENTER))
            addView(powerButton, FrameLayout.LayoutParams(dp(176), dp(176), Gravity.CENTER))
        }
        homeStats = text("↓ 0  ·  ↑ 0  ·  ping —", 14f, cText, false).apply { gravity = Gravity.CENTER }
        homeRx = text("lastRx —", 12f, cMuted, false).apply { gravity = Gravity.CENTER }
        val stats = card().apply {
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(18), dp(16), dp(18), dp(16))
                addView(homeStats)
                addView(spacer(6))
                addView(homeRx)
            })
        }
        body.addView(brand, MATCH_PARENT, WRAP_CONTENT)
        body.addView(homeMode, MATCH_PARENT, WRAP_CONTENT)
        body.addView(spacer(8))
        body.addView(homeStatus, MATCH_PARENT, WRAP_CONTENT)
        body.addView(homeServer, MATCH_PARENT, WRAP_CONTENT)
        body.addView(power, LinearLayout.LayoutParams(MATCH_PARENT, dp(228)))
        body.addView(stats, MATCH_PARENT, WRAP_CONTENT)
        return ScrollView(this).apply { isFillViewport = true; addView(body) }
    }

    private fun buildServersPage(): View {
        val list = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(22), dp(18), dp(18))
            addView(text("Режим и серверы", 22f, cText, true))
            addView(text("KS — IP-туннель с зарубежным выходом. CITP — intent-транспорт через RU.", 12f, cMuted, false).apply {
                setPadding(0, dp(6), 0, dp(16))
            })
        }
        val sel = selected()
        presets().forEach { s ->
            val on = s.id == sel.id
            list.addView(card().apply {
                if (on) strokeColor = if (s.mode == "ks") cAccent else cCitp
                addView(LinearLayout(this@MainActivity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(16), dp(16), dp(16), dp(16))
                    addView(text(s.name, 16f, cText, true))
                    addView(text(s.addr + "  ·  " + s.mode.uppercase(), 12f, cMuted, false))
                    addView(text(s.subtitle, 12f, cMuted, false))
                    addView(MaterialButton(this@MainActivity).apply {
                        text = if (on) "Выбран" else "Выбрать"
                        isAllCaps = false
                        isEnabled = !on || !safeRunning()
                        setTextColor(if (on) cBg else cText)
                        setBackgroundColor(if (on) (if (s.mode == "ks") cAccent else cCitp) else cSurface2)
                        cornerRadius = dp(12)
                        setOnClickListener {
                            if (safeRunning()) { toast("Сначала отключитесь"); return@setOnClickListener }
                            prefs.edit().putString("selected_id", s.id).putString("mode", s.mode)
                                .putString("addr", s.addr).putString("pubkey", s.pubkey).apply()
                            AppLog.i("UI", "selected ${s.id} ${s.mode} ${s.addr}")
                            showTab(TAB_SERVERS)
                        }
                    }, LinearLayout.LayoutParams(MATCH_PARENT, dp(46)).apply { topMargin = dp(10) })
                })
            }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { bottomMargin = dp(12) })
        }
        return ScrollView(this).apply { addView(list) }
    }

    private fun buildLogsPage(): View {
        val wrap = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(18), dp(16), dp(12))
        }
        wrap.addView(text("Журнал", 22f, cText, true))
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(smallBtn("Обновить") { refreshLogs() }, LinearLayout.LayoutParams(0, dp(42), 1f))
            addView(smallBtn("Копировать") { copyLogs() }, LinearLayout.LayoutParams(0, dp(42), 1f))
            addView(smallBtn("Очистить") { AppLog.clear(); refreshLogs() }, LinearLayout.LayoutParams(0, dp(42), 1f))
        }
        wrap.addView(row, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(10); bottomMargin = dp(10) })
        logView = text("", 10f, cMuted, false).apply {
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        logScroll = ScrollView(this).apply {
            isFillViewport = true
            addView(logView, MATCH_PARENT, WRAP_CONTENT)
        }
        wrap.addView(card().apply {
            addView(logScroll, LinearLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT).apply {
                setMargins(dp(10), dp(10), dp(10), dp(10))
            })
        }, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        refreshLogs()
        return wrap
    }

    private fun buildSettingsPage(): View {
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(22), dp(18), dp(20))
            addView(text("Расширенные настройки", 22f, cText, true))
            addView(text("Меняются до следующего подключения.", 12f, cMuted, false).apply { setPadding(0, dp(4), 0, dp(14)) })
        }
        form.addView(switchCard("Российский трафик напрямую (CITP)", prefs.getBoolean("russian_bypass", true)) {
            prefs.edit().putBoolean("russian_bypass", it).apply()
        })
        form.addView(switchCard("Не туннелировать LAN 10/8 172.16 192.168", prefs.getBoolean("bypass_lan", true)) {
            prefs.edit().putBoolean("bypass_lan", it).apply()
        })
        form.addView(switchCard("Подробный журнал", prefs.getBoolean("verbose", true)) {
            prefs.edit().putBoolean("verbose", it).apply(); AppLog.setVerbose(it)
        })
        val dns = input("DNS", prefs.getString("dns", "8.8.8.8").orEmpty())
        val mtuKs = input("MTU KS", prefs.getInt("mtu_ks", 1300).toString())
        val mtuC = input("MTU CITP", prefs.getInt("mtu_citp", 1500).toString())
        form.addView(wrap(dns, "DNS в туннеле"))
        form.addView(wrap(mtuKs, "MTU KS"))
        form.addView(wrap(mtuC, "MTU CITP"))
        form.addView(MaterialButton(this).apply {
            text = "Сохранить"
            isAllCaps = false
            setTextColor(cBg); setBackgroundColor(cAccent); cornerRadius = dp(14)
            setOnClickListener {
                prefs.edit()
                    .putString("dns", dns.text?.toString()?.trim().orEmpty().ifBlank { "8.8.8.8" })
                    .putInt("mtu_ks", mtuKs.text?.toString()?.toIntOrNull() ?: 1300)
                    .putInt("mtu_citp", mtuC.text?.toString()?.toIntOrNull() ?: 1500)
                    .apply()
                toast("Сохранено")
            }
        }, LinearLayout.LayoutParams(MATCH_PARENT, dp(50)).apply { topMargin = dp(8) })
        val pub = try { Mobilecore.pubFromPriv(clientKey) } catch (_: Throwable) { "—" }
        form.addView(card().apply {
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(16), dp(14), dp(16), dp(14))
                addView(text("Ключ устройства (публичный, для allowlist CITP)", 14f, cText, true))
                addView(text(pub, 11f, cAccent, false).apply { typeface = Typeface.MONOSPACE; setTextIsSelectable(true) })
            })
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) })
        form.addView(text("IPv6 не захватывается v4-туннелем. Always-on VPN — в системных настройках Android.", 11f, cMuted, false).apply {
            setPadding(0, dp(14), 0, 0)
        })
        return ScrollView(this).apply { addView(form) }
    }

    private fun onPower() {
        if (safeRunning()) {
            requestStop(); return
        }
        if (!connecting.compareAndSet(false, true)) return
        val s = selected()
        homeStatus?.text = "Подключаем ${s.mode.uppercase()}…"
        homeProgress?.visibility = View.VISIBLE
        powerButton?.isEnabled = false
        AppLog.i("UI", "connect ${s.mode} ${s.addr}")
        handler.postDelayed({
            if (!destroyed && connecting.get() && !safeRunning()) {
                connecting.set(false)
                powerButton?.isEnabled = true
                homeProgress?.visibility = View.GONE
                homeStatus?.text = "Таймаут. См. Logs."
                AppLog.e("UI", "connect watchdog 20s")
            }
        }, 20_000)
        val prep = VpnService.prepare(this)
        if (prep != null) startActivityForResult(prep, VPN_REQUEST) else startVpn()
    }

    private fun startVpn() {
        val s = selected()
        val ksKey = if (s.mode == "ks") loadKsKey() else ""
        if (s.mode == "ks" && ksKey.isEmpty()) {
            connecting.set(false); powerButton?.isEnabled = true; homeProgress?.visibility = View.GONE
            toast("Нет KS-ключа в приложении"); return
        }
        val mtu = if (s.mode == "ks") prefs.getInt("mtu_ks", 1300) else prefs.getInt("mtu_citp", 1500)
        val intent = Intent(this, ChamVpnService::class.java)
            .setAction(ChamVpnService.ACTION_START)
            .putExtra(ChamVpnService.EXTRA_MODE, s.mode)
            .putExtra(ChamVpnService.EXTRA_ADDR, s.addr)
            .putExtra(ChamVpnService.EXTRA_PUBKEY, s.pubkey)
            .putExtra(ChamVpnService.EXTRA_CLIENTKEY, clientKey)
            .putExtra(ChamVpnService.EXTRA_KSKEY, ksKey)
            .putExtra(ChamVpnService.EXTRA_MTU, mtu)
            .putExtra(ChamVpnService.EXTRA_DNS, prefs.getString("dns", "8.8.8.8"))
            .putExtra(ChamVpnService.EXTRA_BYPASS_LAN, prefs.getBoolean("bypass_lan", true))
        ContextCompat.startForegroundService(this, intent)
    }

    private fun loadKsKey(): String {
        return try {
            assets.open("ks-vpn.key").bufferedReader().readText().trim()
        } catch (t: Throwable) {
            AppLog.e("UI", "ks key asset", t); ""
        }
    }

    private fun requestStop() {
        AppLog.i("UI", "disconnect")
        startService(Intent(this, ChamVpnService::class.java).setAction(ChamVpnService.ACTION_STOP))
        homeStatus?.text = "Отключаем…"
        homeProgress?.visibility = View.VISIBLE
        powerButton?.isEnabled = false
        handler.postDelayed({
            if (!destroyed) { connecting.set(false); powerButton?.isEnabled = true; updateUi(safeRunning()) }
        }, 4000)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST && resultCode == RESULT_OK) startVpn()
        else if (requestCode == VPN_REQUEST) {
            connecting.set(false); toast("Нет разрешения VPN"); updateUi(false)
        }
    }

    private fun tick() {
        if (destroyed) return
        val running = safeRunning()
        if (running && connecting.get()) connecting.set(false)
        if (running != lastRunning) {
            lastRunning = running
            if (running) AppLog.i("UI", "state=up mode=${safeMode()}")
            else {
                val err = ChamVpnService.lastError
                if (err.isNotEmpty()) AppLog.e("UI", err)
            }
        }
        updateUi(running)
        if (activeTab == TAB_LOGS) refreshLogs(false)
        handler.postDelayed({ tick() }, 1000)
    }

    private fun updateUi(running: Boolean) {
        val now = System.currentTimeMillis()
        val s = selected()
        homeMode?.apply {
            text = modeLabel(if (running) safeMode().ifBlank { s.mode } else s.mode)
            setTextColor(if ((if (running) safeMode().ifBlank { s.mode } else s.mode) == "ks") cAccent else cCitp)
        }
        homeServer?.text = s.name + "  ·  " + s.addr
        if (running) {
            val upTotal = safeLong { Mobilecore.upBytes() }
            val downTotal = safeLong { Mobilecore.downBytes() }
            var up = 0.0; var down = 0.0
            if (prevT > 0 && now > prevT) {
                val sec = (now - prevT) / 1000.0
                up = (upTotal - prevUp).coerceAtLeast(0) / sec
                down = (downTotal - prevDown).coerceAtLeast(0) / sec
            }
            prevT = now; prevUp = upTotal; prevDown = downTotal
            val ping = safeLong { Mobilecore.rttMs() }
            homeStatus?.apply { text = "Подключено"; setTextColor(cAccent) }
            homeStats?.text = "↓ ${fmtRate(down)}  ·  ↑ ${fmtRate(up)}  ·  ping ${if (ping >= 0) "$ping мс" else "—"}"
            val rx = safeLong { Mobilecore.lastRxSec() }
            homeRx?.text = if (s.mode == "ks" || safeMode() == "ks") {
                if (rx < 0) "KS lastRx: нет (канал ещё не доказан)" else "KS lastRx: ${rx}s"
            } else "CITP mode"
            powerButton?.apply { text = "STOP"; setTextColor(cText); setBackgroundColor(cSurface2); isEnabled = true }
            homeProgress?.visibility = View.GONE
            connecting.set(false)
        } else {
            prevT = 0
            homeStatus?.apply {
                text = if (connecting.get()) "Подключаем…" else "Готов"
                setTextColor(cText)
            }
            homeStats?.text = "↓ 0  ·  ↑ 0  ·  ping —"
            homeRx?.text = ChamVpnService.lastError.ifBlank { "не подключено" }
            if (!connecting.get()) {
                powerButton?.apply { text = "CONNECT"; setTextColor(cBg); setBackgroundColor(cAccent); isEnabled = true }
                homeProgress?.visibility = View.GONE
            }
        }
    }

    private fun refreshLogs(scroll: Boolean = true) {
        val core = try { Mobilecore.logs() } catch (_: Throwable) { "" }
        val file = AppLog.readTail()
        logView?.text = (file + "\n—— core ——\n" + core).takeLast(60_000)
        if (scroll) logScroll?.post { logScroll?.fullScroll(View.FOCUS_DOWN) }
    }

    private fun copyLogs() {
        val f = AppLog.file()
        if (f == null || !f.exists()) { toast("Лог пуст"); return }
        try {
            val uri: Uri = FileProvider.getUriForFile(this, "$packageName.files", f)
            val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_STREAM, uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startActivity(Intent.createChooser(send, "Журнал Chameleon"))
        } catch (t: Throwable) {
            val clip = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            clip.setPrimaryClip(android.content.ClipData.newPlainText("log", AppLog.readTail()))
            toast("Скопировано в буфер")
        }
    }

    private fun safeRunning(): Boolean = try { Mobilecore.isRunning() } catch (_: Throwable) { false }
    private fun safeMode(): String = try { Mobilecore.mode() } catch (_: Throwable) { "" }
    private fun safeLong(b: () -> Long): Long = try { b() } catch (_: Throwable) { -1L }
    private fun modeLabel(m: String) = if (m == "ks") "MODE  KS  ·  KEYSTREAM" else "MODE  CITP  ·  INTENT"
    private fun smallBtn(t: String, a: () -> Unit) = MaterialButton(this).apply {
        text = t; isAllCaps = false; textSize = 11f; setTextColor(cText); setBackgroundColor(cSurface2); cornerRadius = dp(10); setOnClickListener { a() }
    }
    private fun switchCard(label: String, checked: Boolean, on: (Boolean) -> Unit): View {
        val sw = SwitchMaterial(this).apply { text = label; setTextColor(cText); isChecked = checked; setOnCheckedChangeListener { _, v -> on(v) } }
        return card().apply {
            addView(sw, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { setMargins(dp(14), dp(8), dp(14), dp(8)) })
            (layoutParams as? LinearLayout.LayoutParams)?.bottomMargin = dp(10)
        }.also { (it.layoutParams as? LinearLayout.LayoutParams)?.apply { bottomMargin = dp(10) } ?: run {
            it.layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { bottomMargin = dp(10) }
        } }
    }
    private fun input(hint: String, value: String) = TextInputEditText(this).apply {
        setText(value); setTextColor(cText); setHintTextColor(cMuted); this.hint = hint
    }
    private fun wrap(edit: TextInputEditText, hint: String) = TextInputLayout(this).apply {
        this.hint = hint; addView(edit)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { bottomMargin = dp(8) }
    }
    private fun card() = MaterialCardView(this).apply {
        setCardBackgroundColor(cSurface); radius = dp(18).toFloat(); cardElevation = 0f; strokeColor = cSurface2; strokeWidth = dp(1)
    }
    private fun text(v: String, size: Float, color: Int, bold: Boolean) = MaterialTextView(this).apply {
        text = v; textSize = size; setTextColor(color); if (bold) typeface = Typeface.DEFAULT_BOLD
    }
    private fun spacer(h: Int) = View(this).apply { layoutParams = LinearLayout.LayoutParams(1, dp(h)) }
    private fun fmtRate(v: Double) = when {
        v >= 1048576 -> "%.1f МБ/с".format(v / 1048576)
        v >= 1024 -> "%.0f КБ/с".format(v / 1024)
        else -> "%.0f Б/с".format(v)
    }
    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    private fun toast(m: String) = Toast.makeText(this, m, Toast.LENGTH_SHORT).show()
    override fun onDestroy() {
        destroyed = true
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
}
