import io, os, sys, shutil, time

R = "/files/VPN"
BK = os.path.join(R, "backups", "ui-v12-" + time.strftime("%Y%m%d-%H%M%S"))
os.makedirs(BK, exist_ok=True)
MA = os.path.join(R, "android/app/src/main/java/com/chameleonvpn/app/MainActivity.kt")

def sub(s, old, new, tag):
    c = s.count(old)
    if c != 1:
        print("PATCH_FAIL " + tag + " count=" + str(c))
        sys.exit(1)
    print("PATCH_OK " + tag)
    return s.replace(old, new, 1)

s = io.open(MA, encoding="utf-8").read()
shutil.copy2(MA, os.path.join(BK, "MainActivity.kt"))

s = sub(s,
  'import android.os.Looper\nimport android.view.Gravity',
  'import android.os.Looper\nimport android.text.TextUtils\nimport android.util.TypedValue\nimport android.view.Gravity',
  'ui.imports1')

s = sub(s,
  'import androidx.core.content.FileProvider\n',
  'import androidx.core.content.FileProvider\nimport androidx.core.widget.TextViewCompat\n',
  'ui.imports2')

s = sub(s,
  '        private const val TAB_SETTINGS = 4\n',
  '        private const val TAB_SETTINGS = 4\n        private const val TAB_HELP = 5\n',
  'ui.tabconst')

s = sub(s,
  '            setPadding(dp(8), dp(8), dp(8), dp(10))\n            addView(navBtn("Главная", TAB_HOME))\n            addView(navBtn("Серверы", TAB_SERVERS))\n            addView(navBtn("Журнал", TAB_LOGS))\n            addView(navBtn("Настройки", TAB_SETTINGS))',
  '            setPadding(dp(2), dp(4), dp(2), dp(6))\n            addView(navBtn("Главная", TAB_HOME))\n            addView(navBtn("Серверы", TAB_SERVERS))\n            addView(navBtn("Журнал", TAB_LOGS))\n            addView(navBtn("Настройки", TAB_SETTINGS))\n            addView(navBtn("Инструкция", TAB_HELP))',
  'ui.navrow')

s = sub(s,
  '    private fun navBtn(label: String, tab: Int) = MaterialButton(this).apply {\n        text = label\n        isAllCaps = false\n        textSize = 11f\n        setTextColor(if (activeTab == tab) cAccent else cMuted)\n        setBackgroundColor(Color.TRANSPARENT)\n        cornerRadius = dp(10)\n        layoutParams = LinearLayout.LayoutParams(0, dp(44), 1f)\n        setOnClickListener { showTab(tab); refreshNav() }\n    }',
  '    private fun navBtn(label: String, tab: Int) = MaterialButton(this).apply {\n        text = label\n        tag = tab\n        isAllCaps = false\n        // Пять вкладок должны влезать даже в узкий экран: у MaterialButton есть\n        // свои inset-отступы и минимальная ширина по Material-спеке — снимаем их\n        // и разрешаем шрифту автоматически сжиматься.\n        insetTop = 0\n        insetBottom = 0\n        minWidth = 0\n        minimumWidth = 0\n        minHeight = dp(40)\n        iconPadding = 0\n        letterSpacing = 0f\n        maxLines = 1\n        isSingleLine = true\n        ellipsize = TextUtils.TruncateAt.END\n        gravity = Gravity.CENTER\n        setPadding(dp(1), 0, dp(1), 0)\n        TextViewCompat.setAutoSizeTextTypeUniformWithConfiguration(this, 8, 11, 1, TypedValue.COMPLEX_UNIT_SP)\n        setTextColor(if (activeTab == tab) cAccent else cMuted)\n        setBackgroundColor(if (activeTab == tab) cAccentDim else Color.TRANSPARENT)\n        cornerRadius = dp(10)\n        layoutParams = LinearLayout.LayoutParams(0, dp(44), 1f)\n        setOnClickListener { showTab(tab); refreshNav() }\n    }',
  'ui.navbtn')

s = sub(s,
  '    private fun refreshNav() {\n        for (i in 0 until nav.childCount) {\n            val b = nav.getChildAt(i) as MaterialButton\n            val tab = i + 1\n            b.setTextColor(if (activeTab == tab) cAccent else cMuted)\n        }\n    }',
  '    private fun refreshNav() {\n        for (i in 0 until nav.childCount) {\n            val b = nav.getChildAt(i) as? MaterialButton ?: continue\n            val tab = (b.tag as? Int) ?: (i + 1)\n            b.setTextColor(if (activeTab == tab) cAccent else cMuted)\n            b.setBackgroundColor(if (activeTab == tab) cAccentDim else Color.TRANSPARENT)\n        }\n    }',
  'ui.refreshnav')

s = sub(s,
  '            TAB_SETTINGS -> buildSettingsPage()\n            else -> buildHomePage()',
  '            TAB_SETTINGS -> buildSettingsPage()\n            TAB_HELP -> buildHelpPage()\n            else -> buildHomePage()',
  'ui.showtab')

HELP = (
'    private fun helpCard(title: String, bodyText: String): View {\n'
'        val c = card().apply {\n'
'            addView(LinearLayout(this@MainActivity).apply {\n'
'                orientation = LinearLayout.VERTICAL\n'
'                setPadding(dp(16), dp(14), dp(16), dp(14))\n'
'                addView(text(title, 15f, cText, true))\n'
'                addView(text(bodyText, 13f, cMuted, false).apply {\n'
'                    setPadding(0, dp(6), 0, 0)\n'
'                    setLineSpacing(dp(3).toFloat(), 1f)\n'
'                })\n'
'            })\n'
'        }\n'
'        c.layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { bottomMargin = dp(10) }\n'
'        return c\n'
'    }\n'
'\n'
'    private fun buildHelpPage(): View {\n'
'        val body = LinearLayout(this).apply {\n'
'            orientation = LinearLayout.VERTICAL\n'
'            setPadding(dp(18), dp(22), dp(18), dp(24))\n'
'            addView(text("Как пользоваться", 22f, cText, true))\n'
'            addView(text("Короткая инструкция по приложению и туннелю.", 12f, cMuted, false).apply {\n'
'                setPadding(0, dp(6), 0, dp(16))\n'
'            })\n'
'        }\n'
'        body.addView(helpCard("1. Первый запуск",\n'
'            "При первом подключении Android спросит разрешение на VPN — нажмите ОК. " +\n'
'            "На Android 13 и новее разрешите уведомления: в них видно состояние канала " +\n'
'            "и есть кнопка «Отключить». Ключ и адрес сервера уже внутри приложения, " +\n'
'            "вводить ничего не нужно."))\n'
'        body.addView(helpCard("2. Подключение",\n'
'            "Вкладка «Главная» → кнопка «Подключить». Статус станет «Подключено», " +\n'
'            "а в карточке профиля появится «KS lastRx» — возраст последнего пакета от сервера. " +\n'
'            "Значение 0–3 с говорит, что канал живой."))\n'
'        body.addView(helpCard("3. Отключение",\n'
'            "Кнопка «Отключить» на «Главной» или такая же кнопка в уведомлении. " +\n'
'            "Туннель закрывается полностью: ядро отпускает сетевой интерфейс, значок VPN " +\n'
'            "в статус-баре гаснет, трафик снова идёт напрямую. " +\n'
'            "Перезагружать телефон или ждать не нужно."))\n'
'        body.addView(helpCard("4. Что показывают счётчики",\n'
'            "«Скачивание» и «Отправка» — текущая скорость в туннеле. " +\n'
'            "«Задержка» — время отклика сервера. Если скорость нулевая, а lastRx " +\n'
'            "больше 10 с — канал молчит: отключитесь и подключитесь заново."))\n'
'        body.addView(helpCard("5. Серверы",\n'
'            "«KS · RU Exit» — основной режим: личный канал телефона на отдельном порту сервера, " +\n'
'            "он не конфликтует с компьютером — телефон и ПК могут работать одновременно. " +\n'
'            "«CITP · RU Entry» — экспериментальный intent-транспорт. " +\n'
'            "Профиль меняется только при отключённом туннеле."))\n'
'        body.addView(helpCard("6. Настройки",\n'
'            "DNS, MTU и обход локальной сети применяются при следующем подключении. " +\n'
'            "MTU 1300 для KS без причины менять не стоит: при больших значениях " +\n'
'            "крупные пакеты могут не проходить. «Подробный журнал» лучше оставить включённым."))\n'
'        body.addView(helpCard("7. Если что-то не работает",\n'
'            "Порядок действий: отключить и подключить снова → проверить lastRx → " +\n'
'            "вкладка «Журнал» → «Копировать» и отправить лог. " +\n'
'            "В журнале есть и события приложения, и сообщения ядра туннеля."))\n'
'        body.addView(helpCard("Важно знать",\n'
'            "IPv6 через туннель не идёт — захватывается только IPv4. " +\n'
'            "Постоянное подключение включается системно: Настройки Android → VPN → " +\n'
'            "Chameleon → Always-on. Весь трафик идёт через ваш собственный сервер, " +\n'
'            "сторонних сервисов в цепочке нет."))\n'
'        return ScrollView(this).apply { isFillViewport = true; addView(body) }\n'
'    }\n'
'\n'
)

s = sub(s, '    private fun onPower() {', HELP + '    private fun onPower() {', 'ui.helppage')

s = sub(s,
  '        handler.postDelayed({\n            if (!destroyed) { connecting.set(false); powerButton?.isEnabled = true; updateUi(safeRunning()) }\n        }, 4000)\n    }',
  '        pollStopped(0)\n    }\n\n    // Ждём фактического закрытия туннеля и обновляем экран сразу, как только\n    // ядро отпустило интерфейс, а не через фиксированную задержку.\n    private fun pollStopped(elapsed: Int) {\n        if (destroyed) return\n        val stopped = !safeRunning() && ChamVpnService.lifecycle != VpnLifecycleState.STOPPING\n        if (stopped || elapsed >= 6000) {\n            connecting.set(false)\n            powerButton?.isEnabled = true\n            homeProgress?.visibility = View.GONE\n            if (!stopped) AppLog.e("UI", "остановка не подтверждена за 6 с")\n            updateUi(safeRunning())\n            return\n        }\n        handler.postDelayed({ pollStopped(elapsed + 250) }, 250)\n    }',
  'ui.pollstopped')

s = sub(s,
  '            homeStatus?.apply {\n                text = if (connecting.get()) "Подключаем…" else "Готов"\n                setTextColor(cText)\n            }',
  '            val stopping = ChamVpnService.lifecycle == VpnLifecycleState.STOPPING\n            homeStatus?.apply {\n                text = when {\n                    stopping -> "Отключаем…"\n                    connecting.get() -> "Подключаем…"\n                    else -> "Готов"\n                }\n                setTextColor(cText)\n            }',
  'ui.stopstatus')

io.open(MA, "w", encoding="utf-8", newline="").write(s)
print("WROTE MainActivity.kt lines=" + str(s.count(chr(10))))
