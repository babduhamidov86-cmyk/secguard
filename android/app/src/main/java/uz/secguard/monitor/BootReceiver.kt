package uz.secguard.monitor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import uz.secguard.SecGuardApp

/** Qurilma yoqilganda, foydalanuvchi himoyani yoqib qo'ygan bo'lsa, monitorni qayta ishga tushiradi. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val app = context.applicationContext as SecGuardApp
        if (!app.consent.monitorEnabled) return
        try {
            PackageMonitorService.start(context)
        } catch (e: Exception) {
            // Android 12+ da fondan foreground service boshlash cheklanishi mumkin: keyingi ochilishda tiklanadi.
            Log.w("BootReceiver", "Monitor boshlanmadi: ${e.javaClass.simpleName}")
        }
    }
}
