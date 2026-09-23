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
import android.text.TextUtils
import android.util.TypedValue
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
import androidx.core.widget.TextViewCompat
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
    private var homeDown: MaterialTextView? = null
    private var homeUp: MaterialTextView? = null
    private var homePing: MaterialTextView? = null
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

    private val cBg = Color.parseColor("#0B0B0D")
    private val cSurface = Color.parseColor("#151518")
    private val cSurface2 = Color.parseColor("#242429")
    private val cAccent = Color.parseColor("#8B5CF6")
    private val cAccentDim = Color.parseColor("#2A1F45")
    private val cCitp = Color.parseColor("#60A5FA")
    private val cText = Color.parseColor("#FAFAFA")
    private val cMuted = Color.parseColor("#A1A1AA")
    private val cDanger = Color.parseColor("#F87171")

    companion object {
        private const val VPN_REQUEST = 100
        private const val TAB_HOME = 1
        private const val TAB_SERVERS = 2
        private const val TAB_LOGS = 3
        private const val TAB_SETTINGS = 4
        private const val TAB_HELP = 5
        const val CITP_PUB = "LaK1-DXOOO0ABWI2DqNkZpeNtmAHiCjJ7OiQHTR8OXY"
    }

    private fun presets(): List<ServerProfile> = listOf(
        ServerProfile(
            id = "ks-ru",
            name = "KS · RU Exit",
            mode = "ks",
            addr = "192.0.2.10:51822",
            subtitle = "Личный канал телефона · независим от ПК"
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
            setPadding(dp(2), dp(4), dp(2), dp(6))
            addView(navBtn("Главная", TAB_HOME))
            addView(navBtn("Серверы", TAB_SERVERS))
            addView(navBtn("Журнал", TAB_LOGS))
            addView(navBtn("Настройки", TAB_SETTINGS))
            addView(navBtn("Инструкция", TAB_HELP))
        }
        root.addView(pageHost, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        root.addView(nav, MATCH_PARENT, WRAP_CONTENT)
        setContentView(root)
    }

    private fun navBtn(label: String, tab: Int) = MaterialButton(this).apply {
        text = label
        tag = tab
        isAllCaps = false
        // Пять вкладок должны влезать даже в узкий экран: у MaterialButton есть
        // свои inset-отступы и минимальная ширина по Material-спеке — снимаем их
        // и разрешаем шрифту автоматически сжиматься.
        insetTop = 0
        insetBottom = 0
        minWidth = 0
        minimumWidth = 0
        minHeight = dp(40)
        iconPadding = 0
        letterSpacing = 0f
        maxLines = 1
        isSingleLine = true
        ellipsize = TextUtils.TruncateAt.END
        gravity = Gravity.CENTER
        setPadding(dp(1), 0, dp(1), 0)
        TextViewCompat.setAutoSizeTextTypeUniformWithConfiguration(this, 8, 11, 1, TypedValue.COMPLEX_UNIT_SP)
        setTextColor(if (activeTab == tab) cAccent else cMuted)
        setBackgroundColor(if (activeTab == tab) cAccentDim else Color.TRANSPARENT)
        cornerRadius = dp(10)
        layoutParams = LinearLayout.LayoutParams(0, dp(44), 1f)
        setOnClickListener { showTab(tab); refreshNav() }
    }

    private fun refreshNav() {
        for (i in 0 until nav.childCount) {
            val b = nav.getChildAt(i) as? MaterialButton ?: continue
            val tab = (b.tag as? Int) ?: (i + 1)
            b.setTextColor(if (activeTab == tab) cAccent else cMuted)
            b.setBackgroundColor(if (activeTab == tab) cAccentDim else Color.TRANSPARENT)
        }
    }

    private fun showTab(tab: Int) {
        activeTab = tab
        pageHost.removeAllViews()
        homeStatus = null; homeServer = null; homeMode = null; homeStats = null
        homeDown = null; homeUp = null; homePing = null; homeRx = null; powerButton = null; homeProgress = null; logView = null; logScroll = null
        pageHost.addView(when (tab) {
            TAB_SERVERS -> buildServersPage()
            TAB_LOGS -> buildLogsPage()
            TAB_SETTINGS -> buildSettingsPage()
            TAB_HELP -> buildHelpPage()
            else -> buildHomePage()
        }, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        refreshNav()
        updateUi(safeRunning())
    }

    private fun buildHomePage(): View {
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(24))
        }
        val top = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(text("Chameleon", 24f, cText, true), LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            addView(text("PRIVATE NETWORK", 10f, cMuted, true).apply { letterSpacing = .12f })
        }
        val hero = card().apply {
            setCardBackgroundColor(cSurface)
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(22), dp(22), dp(22), dp(22))
                homeMode = text(modeLabel(selected().mode), 11f, if (selected().mode == "ks") cAccent else cCitp, true).apply { letterSpacing = .08f }
                homeStatus = text("Готово к подключению", 26f, cText, true).apply { setPadding(0, dp(12), 0, dp(6)) }
                addView(homeMode)
                addView(homeStatus)
                addView(text("Шифрованный канал без сторонних сервисов", 14f, cMuted, false))
                powerButton = MaterialButton(this@MainActivity).apply {
                    text = "Подключить"
                    textSize = 16f
                    isAllCaps = false
                    setTextColor(Color.WHITE)
                    setBackgroundColor(cAccent)
                    cornerRadius = dp(16)
                    minHeight = dp(58)
                    setOnClickListener { onPower() }
                }
                homeProgress = CircularProgressIndicator(this@MainActivity).apply {
                    visibility = View.GONE
                    setIndicatorColor(Color.WHITE)
                    indicatorSize = dp(24)
                    trackThickness = dp(2)
                }
                addView(powerButton, LinearLayout.LayoutParams(MATCH_PARENT, dp(58)).apply { topMargin = dp(24) })
            })
        }
        val serverCard = card().apply {
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(18), dp(16), dp(18), dp(16))
                addView(text("АКТИВНЫЙ ПРОФИЛЬ", 10f, cMuted, true).apply { letterSpacing = .12f })
                homeServer = text(selected().name, 17f, cText, true).apply { setPadding(0, dp(8), 0, dp(3)) }
                addView(homeServer)
                addView(text(selected().addr, 13f, cMuted, false))
                homeRx = text("Канал не активен", 12f, cMuted, false).apply { setPadding(0, dp(8), 0, 0) }
                addView(homeRx)
            })
        }
        val stats = card().apply {
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(dp(8), dp(16), dp(8), dp(16))
                homeDown = statCell(this, "СКАЧИВАНИЕ", "0 Б/с")
                homeUp = statCell(this, "ОТПРАВКА", "0 Б/с")
                homePing = statCell(this, "ЗАДЕРЖКА", "—")
                addView(homeDown, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
                addView(homeUp, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
                addView(homePing, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            })
        }
        homeStats = text("", 1f, Color.TRANSPARENT, false)
        body.addView(top, MATCH_PARENT, WRAP_CONTENT)
        body.addView(hero, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(28) })
        body.addView(serverCard, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(14) })
        body.addView(stats, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(14) })
        return ScrollView(this).apply { isFillViewport = true; addView(body) }
    }

    private fun statCell(parent: LinearLayout, label: String, value: String): MaterialTextView {
        return text("$label\n$value", 12f, cText, true).apply {
            gravity = Gravity.CENTER
            setLineSpacing(dp(4).toFloat(), 1f)
        }
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

    private fun helpCard(title: String, bodyText: String): View {
        val c = card().apply {
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(16), dp(14), dp(16), dp(14))
                addView(text(title, 15f, cText, true))
                addView(text(bodyText, 13f, cMuted, false).apply {
                    setPadding(0, dp(6), 0, 0)
                    setLineSpacing(dp(3).toFloat(), 1f)
                })
            })
        }
        c.layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { bottomMargin = dp(10) }
        return c
    }

    private fun buildHelpPage(): View {
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(22), dp(18), dp(24))
            addView(text("Как пользоваться", 22f, cText, true))
            addView(text("Короткая инструкция по приложению и туннелю.", 12f, cMuted, false).apply {
                setPadding(0, dp(6), 0, dp(16))
            })
        }
        body.addView(helpCard("1. Первый запуск",
            "При первом подключении Android спросит разрешение на VPN — нажмите ОК. " +
            "На Android 13 и новее разрешите уведомления: в них видно состояние канала " +
            "и есть кнопка «Отключить». Ключ и адрес сервера уже внутри приложения, " +
            "вводить ничего не нужно."))
        body.addView(helpCard("2. Подключение",
            "Вкладка «Главная» → кнопка «Подключить». Статус станет «Подключено», " +
            "а в карточке профиля появится «KS lastRx» — возраст последнего пакета от сервера. " +
            "Значение 0–3 с говорит, что канал живой."))
        body.addView(helpCard("3. Отключение",
            "Кнопка «Отключить» на «Главной» или такая же кнопка в уведомлении. " +
            "Туннель закрывается полностью: ядро отпускает сетевой интерфейс, значок VPN " +
            "в статус-баре гаснет, трафик снова идёт напрямую. " +
            "Перезагружать телефон или ждать не нужно."))
        body.addView(helpCard("4. Что показывают счётчики",
            "«Скачивание» и «Отправка» — текущая скорость в туннеле. " +
            "«Задержка» — время отклика сервера. Если скорость нулевая, а lastRx " +
            "больше 10 с — канал молчит: отключитесь и подключитесь заново."))
        body.addView(helpCard("5. Серверы",
            "«KS · RU Exit» — основной режим: личный канал телефона на отдельном порту сервера, " +
            "он не конфликтует с компьютером — телефон и ПК могут работать одновременно. " +
            "«CITP · RU Entry» — экспериментальный intent-транспорт. " +
            "Профиль меняется только при отключённом туннеле."))
        body.addView(helpCard("6. Настройки",
            "DNS, MTU и обход локальной сети применяются при следующем подключении. " +
            "MTU 1300 для KS без причины менять не стоит: при больших значениях " +
            "крупные пакеты могут не проходить. «Подробный журнал» лучше оставить включённым."))
        body.addView(helpCard("7. Если что-то не работает",
            "Порядок действий: отключить и подключить снова → проверить lastRx → " +
            "вкладка «Журнал» → «Копировать» и отправить лог. " +
            "В журнале есть и события приложения, и сообщения ядра туннеля."))
        body.addView(helpCard("Важно знать",
            "IPv6 через туннель не идёт — захватывается только IPv4. " +
            "Постоянное подключение включается системно: Настройки Android → VPN → " +
            "Chameleon → Always-on. Весь трафик идёт через ваш собственный сервер, " +
            "сторонних сервисов в цепочке нет."))
        return ScrollView(this).apply { isFillViewport = true; addView(body) }
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
        pollStopped(0)
    }

    // Ждём фактического закрытия туннеля и обновляем экран сразу, как только
    // ядро отпустило интерфейс, а не через фиксированную задержку.
    private fun pollStopped(elapsed: Int) {
        if (destroyed) return
        val stopped = !safeRunning() && ChamVpnService.lifecycle != VpnLifecycleState.STOPPING
        if (stopped || elapsed >= 6000) {
            connecting.set(false)
            powerButton?.isEnabled = true
            homeProgress?.visibility = View.GONE
            if (!stopped) AppLog.e("UI", "остановка не подтверждена за 6 с")
            updateUi(safeRunning())
            return
        }
        handler.postDelayed({ pollStopped(elapsed + 250) }, 250)
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
            homeDown?.text = "СКАЧИВАНИЕ\n${fmtRate(down)}"
            homeUp?.text = "ОТПРАВКА\n${fmtRate(up)}"
            homePing?.text = "ЗАДЕРЖКА\n${if (ping >= 0) "$ping мс" else "—"}"
            val rx = safeLong { Mobilecore.lastRxSec() }
            homeRx?.text = if (s.mode == "ks" || safeMode() == "ks") {
                if (rx < 0) "KS lastRx: нет (канал ещё не доказан)" else "KS lastRx: ${rx}s"
            } else "CITP mode"
            powerButton?.apply { text = "Отключить"; setTextColor(cText); setBackgroundColor(cSurface2); isEnabled = true }
            homeProgress?.visibility = View.GONE
            connecting.set(false)
        } else {
            prevT = 0
            val stopping = ChamVpnService.lifecycle == VpnLifecycleState.STOPPING
            homeStatus?.apply {
                text = when {
                    stopping -> "Отключаем…"
                    connecting.get() -> "Подключаем…"
                    else -> "Готов"
                }
                setTextColor(cText)
            }
            homeDown?.text = "СКАЧИВАНИЕ\n0 Б/с"
            homeUp?.text = "ОТПРАВКА\n0 Б/с"
            homePing?.text = "ЗАДЕРЖКА\n—"
            homeRx?.text = ChamVpnService.lastError.ifBlank { "не подключено" }
            if (!connecting.get()) {
                powerButton?.apply { text = "Подключить"; setTextColor(Color.WHITE); setBackgroundColor(cAccent); isEnabled = true }
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
    private fun modeLabel(m: String) = if (m == "ks") "KS · ЗАЩИЩЁННЫЙ ТУННЕЛЬ" else "CITP · INTENT TRANSPORT"
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
        setCardBackgroundColor(cSurface); radius = dp(16).toFloat(); cardElevation = 0f; strokeColor = cSurface2; strokeWidth = dp(1)
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
