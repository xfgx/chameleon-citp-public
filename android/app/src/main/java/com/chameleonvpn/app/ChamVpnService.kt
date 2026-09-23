package com.chameleonvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import mobilecore.Mobilecore
import mobilecore.Protector
import java.util.concurrent.atomic.AtomicBoolean

enum class VpnLifecycleState { STOPPED, STARTING, RUNNING, STOPPING, FAILED }

class ChamVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private val stateLock = Any()
    private val cleanupStarted = AtomicBoolean(false)
    @Volatile private var state = VpnLifecycleState.STOPPED

    companion object {
        const val ACTION_START = "com.chameleonvpn.app.START"
        const val ACTION_STOP = "com.chameleonvpn.app.STOP"
        const val EXTRA_MODE = "mode"
        const val EXTRA_ADDR = "addr"
        const val EXTRA_PUBKEY = "pubkey"
        const val EXTRA_CLIENTKEY = "clientkey"
        const val EXTRA_KSKEY = "kskey"
        const val EXTRA_MTU = "mtu"
        const val EXTRA_DNS = "dns"
        const val EXTRA_BYPASS_LAN = "bypass_lan"
        private const val CHANNEL_ID = "chameleon_vpn"
        private const val NOTIFICATION_ID = 41
        @Volatile var lastError: String = ""
            private set

        /** Реальное состояние туннеля для UI (обновляется синхронно с жизненным циклом). */
        @Volatile var lifecycle: VpnLifecycleState = VpnLifecycleState.STOPPED
            private set
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            AppLog.i("VPN", "stop requested")
            stopVpn()
            return START_NOT_STICKY
        }
        synchronized(stateLock) {
            if (state == VpnLifecycleState.RUNNING || state == VpnLifecycleState.STARTING) {
                AppLog.d("VPN", "start ignored, state=$state")
                return START_NOT_STICKY
            }
            state = VpnLifecycleState.STARTING
            lifecycle = VpnLifecycleState.STARTING
            cleanupStarted.set(false)
            lastError = ""
        }
        val mode = intent?.getStringExtra(EXTRA_MODE).orEmpty().ifBlank { "citp" }
        val addr = intent?.getStringExtra(EXTRA_ADDR).orEmpty()
        val pubkey = intent?.getStringExtra(EXTRA_PUBKEY).orEmpty()
        val clientkey = intent?.getStringExtra(EXTRA_CLIENTKEY).orEmpty()
        val kskey = intent?.getStringExtra(EXTRA_KSKEY).orEmpty()
        val mtu = intent?.getIntExtra(EXTRA_MTU, if (mode == "ks") 1300 else 1500) ?: 1500
        val dns = intent?.getStringExtra(EXTRA_DNS).orEmpty().ifBlank { "8.8.8.8" }
        val bypassLan = intent?.getBooleanExtra(EXTRA_BYPASS_LAN, true) ?: true

        if (addr.isBlank()) {
            fail("не задан адрес сервера")
            return START_NOT_STICKY
        }
        if (mode == "citp" && (pubkey.isBlank() || clientkey.isBlank())) {
            fail("CITP: нет ключа ноды или устройства")
            return START_NOT_STICKY
        }
        if (mode == "ks" && kskey.isBlank()) {
            fail("KS: нет мастер-ключа")
            return START_NOT_STICKY
        }

        startForegroundNotification(if (mode == "ks") "KS: подключение…" else "CITP: подключение…")
        AppLog.i("VPN", "start mode=$mode addr=$addr mtu=$mtu dns=$dns lan=$bypassLan")

        Thread({
            try {
                val tunAddr = if (mode == "ks") "10.99.1.1" else "10.66.0.2"
                val builder = Builder()
                    .setSession("Chameleon $mode")
                    .setMtu(mtu.coerceIn(1280, 1500))
                    .addAddress(tunAddr, 24)
                    .addDnsServer(dns)
                    .allowFamily(OsConstants.AF_INET)
                    .setBlocking(true)
                if (bypassLan) {
                    builder.addRoute("0.0.0.0", 1)
                    builder.addRoute("128.0.0.0", 1)
                } else {
                    builder.addRoute("0.0.0.0", 0)
                }
                val established = builder.establish()
                if (established == null) {
                    fail("VpnService.establish() вернул null")
                    return@Thread
                }
                tun = established
                val coreFd = ParcelFileDescriptor.dup(established.fileDescriptor).detachFd()
                val vpn = this@ChamVpnService
                val protector = object : Protector {
                    override fun protect(fd: Int): Boolean {
                        val ok = vpn.protect(fd)
                        if (!ok) AppLog.e("VPN", "protect($fd)=false — возможна петля")
                        return ok
                    }
                }
                val error = if (mode == "ks") {
                    Mobilecore.startKS(addr, kskey, coreFd, protector)
                } else {
                    Mobilecore.start(addr, pubkey, clientkey, coreFd, protector)
                }
                if (error.isNotEmpty()) {
                    fail("$mode start: $error")
                } else if (!cleanupStarted.get()) {
                    synchronized(stateLock) { state = VpnLifecycleState.RUNNING }
                    lifecycle = VpnLifecycleState.RUNNING
                    updateNotification(if (mode == "ks") "KS подключён" else "CITP подключён")
                    AppLog.i("VPN", "$mode running")
                }
            } catch (t: Throwable) {
                fail("поток VPN: ${t.message}", t)
            }
        }, "chameleon-vpn-core").start()
        return START_NOT_STICKY
    }

    private fun fail(message: String, error: Throwable? = null) {
        lastError = message
        AppLog.e("VPN", message, error)
        synchronized(stateLock) { state = VpnLifecycleState.FAILED }
        lifecycle = VpnLifecycleState.FAILED
        stopVpn()
    }

    private fun stopVpn() {
        if (!cleanupStarted.compareAndSet(false, true)) return
        synchronized(stateLock) { state = VpnLifecycleState.STOPPING }
        lifecycle = VpnLifecycleState.STOPPING
        AppLog.i("VPN", "stopping")
        // Порядок критичен: ядро обязано отпустить свой дубликат tun-fd, иначе
        // Android продолжит держать VPN-интерфейс поднятым и трафик будет уходить
        // в мёртвый туннель даже после нажатия «Отключить».
        try { Mobilecore.stop() } catch (t: Throwable) { AppLog.e("VPN", "Mobilecore.stop", t) }
        try { tun?.close() } catch (t: Throwable) { AppLog.e("VPN", "tun.close", t) }
        tun = null
        AppLog.i("VPN", "туннель отпущен, сетевой интерфейс закрыт")
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
            else @Suppress("DEPRECATION") stopForeground(true)
        } catch (_: Throwable) {}
        getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        synchronized(stateLock) { state = VpnLifecycleState.STOPPED }
        lifecycle = VpnLifecycleState.STOPPED
        stopSelf()
    }

    override fun onRevoke() { AppLog.i("VPN", "revoked"); stopVpn(); super.onRevoke() }
    override fun onDestroy() { stopVpn(); super.onDestroy() }

    private fun createNotification(text: String): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "VPN", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Состояние туннеля"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        val open = PendingIntent.getActivity(
            this, 1, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 2, Intent(this, ChamVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val b = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) Notification.Builder(this, CHANNEL_ID)
        else @Suppress("DEPRECATION") Notification.Builder(this)
        return b.setSmallIcon(R.drawable.ic_chameleon)
            .setContentTitle("Chameleon")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(Notification.Action.Builder(null, "Отключить", stop).build())
            .build()
    }

    private fun startForegroundNotification(text: String) {
        val n = createNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else startForeground(NOTIFICATION_ID, n)
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, createNotification(text))
    }
}
