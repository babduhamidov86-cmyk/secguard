package uz.secguard.monitor

import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import uz.secguard.SecGuardApp
import uz.secguard.core.RiskScoring

/**
 * Lokal xavfsizlik monitori (Foreground Service).
 *
 * MUHIM: ACTION_PACKAGE_ADDED Android 8+ da manifest orqali olinmaydi (implicit broadcast cheklovi),
 * shuning uchun qabul qiluvchi xizmat ichida DINAMIK ro'yxatdan o'tkaziladi.
 * MUHIM: Android o'rnatishni "ushlab qolish"/bloklashga ruxsat bermaydi. Bu xizmat o'rnatishdan KEYIN
 * darhol tekshiradi va xavfli bo'lsa ogohlantiradi; o'chirishni foydalanuvchi o'zi tasdiqlaydi.
 */
class PackageMonitorService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var registered = false

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != Intent.ACTION_PACKAGE_ADDED) return
            if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return // yangilanish, yangi o'rnatish emas
            val pkg = intent.data?.schemeSpecificPart ?: return
            if (pkg == packageName) return
            scan(pkg)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val app = application as SecGuardApp
        Notifier.ensureChannels(this)
        val n = Notifier.foreground(this)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(Notifier.ID_FOREGROUND, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(Notifier.ID_FOREGROUND, n)
        }
        if (!app.consent.accepted || !app.consent.monitorEnabled) { // rozilik bekor qilingan bo'lsa to'xtaymiz
            stopSelf(); return START_NOT_STICKY
        }
        if (!registered) {
            val filter = IntentFilter(Intent.ACTION_PACKAGE_ADDED).apply { addDataScheme("package") }
            ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
            registered = true
        }
        return START_STICKY
    }

    private fun scan(pkg: String) {
        val app = application as SecGuardApp
        scope.launch {
            try {
                val report = app.scans.scanInstalled(pkg)
                if (report.score >= RiskScoring.ALERT_THRESHOLD) Notifier.showAlert(this@PackageMonitorService, report)
            } catch (e: PackageManager.NameNotFoundException) {
                // Paket ko'rinishi (package visibility) cheklovi: manifestdagi <queries> izohiga qarang.
                Log.w(TAG, "Paket ko'rinmadi: $pkg")
            } catch (e: Exception) {
                Log.w(TAG, "Tekshiruv xatosi: ${e.javaClass.simpleName}")
            }
        }
    }

    override fun onDestroy() {
        if (registered) runCatching { unregisterReceiver(receiver) }
        registered = false
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        private const val TAG = "PackageMonitor"

        fun start(ctx: Context) =
            ContextCompat.startForegroundService(ctx, Intent(ctx, PackageMonitorService::class.java))

        fun stop(ctx: Context) { ctx.stopService(Intent(ctx, PackageMonitorService::class.java)) }
    }
}
