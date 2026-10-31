package uz.secguard.data

import android.content.Context
import android.content.SharedPreferences
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uz.secguard.SecGuardApp
import java.util.concurrent.TimeUnit

/** Serverdagi yangi xavfli fayllar/domenlar bazasini lokal SQLite bilan sinxronlaydi (faqat yuklab olish). */
class SyncRepository(
    private val db: BlacklistDb,
    private val api: ApiClient,
    private val prefs: SharedPreferences,
) {
    /** @return qabul qilingan yozuvlar soni */
    suspend fun sync(): Int = withContext(Dispatchers.IO) {
        var since = prefs.getLong(KEY_SINCE, 0L)
        var total = 0
        var pages = 0
        while (pages++ < MAX_PAGES) {
            val page = api.syncPage(since)
            db.applyChanges(page.items)
            total += page.items.size
            val progressed = page.nextSince != since
            since = page.nextSince
            prefs.edit().putLong(KEY_SINCE, since).apply()
            if (!page.hasMore || !progressed) break
        }
        total
    }

    private companion object {
        const val KEY_SINCE = "since_ms"
        const val MAX_PAGES = 50
    }
}

class SyncWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        val app = applicationContext as SecGuardApp
        if (!app.consent.accepted) return Result.success()
        return try {
            app.sync.sync()
            Result.success()
        } catch (e: Exception) {
            if (runAttemptCount < 3) Result.retry() else Result.failure()
        }
    }

    companion object {
        fun schedule(context: Context) {
            val req = PeriodicWorkRequestBuilder<SyncWorker>(6, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork("blacklist_sync", ExistingPeriodicWorkPolicy.KEEP, req)
        }
    }
}
