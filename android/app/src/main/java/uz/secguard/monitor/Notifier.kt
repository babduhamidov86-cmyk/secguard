package uz.secguard.monitor

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import uz.secguard.core.RiskReport
import uz.secguard.ui.MainActivity

object Notifier {
    private const val CH_MONITOR = "monitor"
    private const val CH_ALERT = "alerts"
    const val ID_FOREGROUND = 1

    fun ensureChannels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH_MONITOR, "Himoya holati", NotificationManager.IMPORTANCE_LOW))
        nm.createNotificationChannel(NotificationChannel(CH_ALERT, "Xavfsizlik ogohlantirishlari", NotificationManager.IMPORTANCE_HIGH))
    }

    /** Foreground service uchun doimiy bildirishnoma (shaffoflik: foydalanuvchi himoya yoqilganini ko'radi). */
    fun foreground(ctx: Context): Notification =
        NotificationCompat.Builder(ctx, CH_MONITOR)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock) // o'z ikonkangiz bilan almashtiring
            .setContentTitle("SecGuard himoyasi yoqilgan")
            .setContentText("Yangi o'rnatilgan ilovalar qurilmada tekshiriladi")
            .setOngoing(true)
            .setContentIntent(openApp(ctx, 0, null))
            .build()

    @SuppressLint("MissingPermission") // areNotificationsEnabled() tekshiriladi
    fun showAlert(ctx: Context, r: RiskReport) {
        val nm = NotificationManagerCompat.from(ctx)
        if (!nm.areNotificationsEnabled()) return
        val pkg = r.packageName ?: return
        val name = r.appName ?: pkg
        val top = r.reasons.take(5).joinToString("\n") { "• ${it.text}" }

        val details = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", pkg, null))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val detailsPi = PendingIntent.getActivity(ctx, pkg.hashCode(), details, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

        val n = NotificationCompat.Builder(ctx, CH_ALERT)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Shubhali ilova: $name")
            .setContentText("Xavf darajasi: ${r.score}% (${r.level})")
            .setStyle(NotificationCompat.BigTextStyle().bigText("Xavf darajasi: ${r.score}% (${r.level})\n$top"))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(openApp(ctx, pkg.hashCode() + 1, pkg))
            .addAction(0, "Ilova sozlamalari / o'chirish", detailsPi)
            .build()
        nm.notify(pkg.hashCode(), n)
    }

    private fun openApp(ctx: Context, code: Int, pkg: String?): PendingIntent {
        val i = Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_NEW_TASK)
        if (pkg != null) i.putExtra(MainActivity.EXTRA_PACKAGE, pkg)
        return PendingIntent.getActivity(ctx, code, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }
}
