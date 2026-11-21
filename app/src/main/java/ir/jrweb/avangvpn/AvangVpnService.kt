package ir.jrweb.avangvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import io.nekohasekai.libbox.BoxService
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.StringIterator
import java.io.File

class AvangVpnService : VpnService(), PlatformInterface {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var boxService: BoxService? = null

    override fun onCreate() {
        super.onCreate()
        val workDir = File(filesDir, "singbox").apply { mkdirs() }
        Libbox.setup(workDir.absolutePath, workDir.absolutePath, workDir.absolutePath, false)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP_VPN") {
            stopVpn()
            return START_NOT_STICKY
        }

        val configName = intent?.getStringExtra("CONFIG_NAME") ?: "Avang Server"
        val jsonConfig = intent?.getStringExtra("JSON_CONFIG") ?: return START_NOT_STICKY

        startForegroundNotification(configName)
        startSingBox(jsonConfig)
        return START_STICKY
    }

    private fun startForegroundNotification(serverName: String) {
        val channelId = "avang_vpn_channel"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(channelId, "آونگ وی‌پی‌ان", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        val notification = builder
            .setContentTitle("آونگ وی‌پی‌ان متصل است")
            .setContentText("سرور فعال: $serverName")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
        startForeground(101, notification)
    }

    private fun startSingBox(jsonConfig: String) {
        try {
            boxService?.close()
            boxService = Libbox.newService(jsonConfig, this)
            boxService?.start()
        } catch (e: Exception) {
            e.printStackTrace()
            stopVpn()
        }
    }

    override fun openTun(options: TunOptions): Int {
        val builder = Builder()
        builder.setSession("AvangVPN")
        builder.setMtu(options.mtu)
        builder.addAddress("172.19.0.1", 30)
        builder.addRoute("0.0.0.0", 0)
        builder.addDnsServer("1.1.1.1")
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }
        vpnInterface = builder.establish()
        return vpnInterface?.fd ?: -1
    }

    override fun autoDetectInterfaceControl(fd: Int) {
        protect(fd)
    }

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true
    override fun useProcFS(): Boolean = false
    override fun findConnectionOwner(p0: Int, p1: String?, p2: Int, p3: String?, p4: Int): Int = -1
    override fun packageNameByUid(uid: Int): String = packageManager.getNameForUid(uid) ?: ""
    override fun uidByPackageName(pkg: String?): Int = 0
    override fun startDefaultInterfaceMonitor(p0: io.nekohasekai.libbox.InterfaceUpdateListener?) {}
    override fun closeDefaultInterfaceMonitor(p0: io.nekohasekai.libbox.InterfaceUpdateListener?) {}
    override fun getInterfaces(): io.nekohasekai.libbox.NetworkInterfaceIterator? = null
    override fun underNetworkExtension(): Boolean = false
    override fun includeAllNetworks(): Boolean = false
    override fun readWIFIState(): io.nekohasekai.libbox.WIFIState? = null
    override fun clearDNSCache() {}
    override fun sendNotification(p0: io.nekohasekai.libbox.Notification?) {}
    override fun localDNSTransport(): io.nekohasekai.libbox.LocalDNSTransport? = null
    override fun systemCertificates(): StringIterator? = null
    override fun writeLog(message: String?) {}

    private fun stopVpn() {
        try {
            boxService?.close()
            boxService = null
            vpnInterface?.close()
            vpnInterface = null
        } catch (_: Exception) {
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}