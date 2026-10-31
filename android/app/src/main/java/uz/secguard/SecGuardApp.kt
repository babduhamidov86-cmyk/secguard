package uz.secguard

import android.app.Application
import uz.secguard.core.ApkStaticAnalyzer
import uz.secguard.data.ApiClient
import uz.secguard.data.BlacklistDb
import uz.secguard.data.ConsentStore
import uz.secguard.data.ScanRepository
import uz.secguard.data.SyncRepository
import uz.secguard.data.SyncWorker

/** Oddiy qo'lda yozilgan bog'liqliklar konteyneri (DI kutubxonasiz). */
class SecGuardApp : Application() {
    val consent by lazy { ConsentStore(this) }
    val blacklist by lazy { BlacklistDb(this) }
    val api by lazy { ApiClient() }
    val analyzer by lazy { ApkStaticAnalyzer(this, blacklist) }
    val scans by lazy { ScanRepository(analyzer, api, consent, blacklist) }
    val sync by lazy { SyncRepository(blacklist, api, getSharedPreferences("secguard_sync", MODE_PRIVATE)) }

    override fun onCreate() {
        super.onCreate()
        if (consent.accepted) SyncWorker.schedule(this)
    }
}
