package uz.secguard.ui

import android.app.Application
import android.content.Intent
import android.net.Uri
import androidx.core.content.IntentCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import uz.secguard.SecGuardApp
import uz.secguard.core.InvalidApkException
import uz.secguard.core.RiskReport
import uz.secguard.core.UrlGuard
import uz.secguard.data.SyncWorker
import uz.secguard.monitor.PackageMonitorService

data class UiState(
    val consented: Boolean = false,
    val monitorEnabled: Boolean = false,
    val busy: Boolean = false,
    val urlInput: String = "",
    val urlResult: UrlGuard.Result? = null,
    val report: RiskReport? = null,
    val message: String? = null,
    val blacklistCount: Int = 0,
)

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val graph = app as SecGuardApp
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()
    private var pending: Intent? = null

    init { refresh() }

    private fun refresh() = _state.update {
        it.copy(
            consented = graph.consent.accepted,
            monitorEnabled = graph.consent.monitorEnabled,
            blacklistCount = if (graph.consent.accepted) graph.blacklist.count() else 0,
        )
    }

    // ---------- Rozilik ----------
    fun acceptConsent(serverLookup: Boolean, apkUpload: Boolean) {
        graph.consent.accept(serverLookup, apkUpload)
        SyncWorker.schedule(graph)
        refresh()
        syncNow()
        pending?.let { handleIntent(it); pending = null }
    }

    fun revokeConsent() {
        PackageMonitorService.stop(graph)
        graph.consent.revokeAll()
        graph.blacklist.clear()
        _state.value = UiState()
    }

    // ---------- Monitor ----------
    fun setMonitor(enabled: Boolean) {
        graph.consent.monitorEnabled = enabled
        if (enabled) PackageMonitorService.start(graph) else PackageMonitorService.stop(graph)
        refresh()
    }

    // ---------- URL ----------
    fun onUrlChange(v: String) = _state.update { it.copy(urlInput = v) }

    fun checkUrl() {
        val raw = _state.value.urlInput
        if (raw.isBlank()) return
        launchBusy {
            val r = graph.scans.checkUrl(raw)
            _state.update { it.copy(urlResult = r, message = null) }
        }
    }

    // ---------- APK ----------
    fun scanApk(uri: Uri) = launchBusy {
        try {
            val r = graph.scans.scanApk(uri)
            _state.update { it.copy(report = r, message = null) }
        } catch (e: InvalidApkException) {
            _state.update { it.copy(message = e.message) }
        }
    }

    fun scanInstalled(pkg: String) = launchBusy {
        try {
            _state.update { it.copy(report = graph.scans.scanInstalled(pkg), message = null) }
        } catch (e: Exception) {
            _state.update { it.copy(message = "Ilovani tekshirib bo'lmadi") }
        }
    }

    // ---------- Sinxronizatsiya ----------
    fun syncNow() = launchBusy {
        try {
            graph.sync.sync()
            _state.update { it.copy(blacklistCount = graph.blacklist.count(), message = "Qora ro'yxat yangilandi") }
        } catch (e: Exception) {
            _state.update { it.copy(message = "Sinxronizatsiya amalga oshmadi (tarmoq?)") }
        }
    }

    // ---------- Ulashilgan kontent (Telegram -> Ulashish) ----------
    fun handleIntent(intent: Intent?) {
        intent ?: return
        if (!graph.consent.accepted) { pending = intent; return }
        when {
            intent.action == Intent.ACTION_SEND && intent.type == "text/plain" -> {
                val text = intent.getStringExtra(Intent.EXTRA_TEXT).orEmpty()
                val link = Regex("https?://\\S+").find(text)?.value ?: text.trim()
                _state.update { it.copy(urlInput = link) }
                checkUrl()
            }
            intent.action == Intent.ACTION_SEND && intent.type == "application/vnd.android.package-archive" -> {
                IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)?.let(::scanApk)
            }
            intent.hasExtra(MainActivity.EXTRA_PACKAGE) -> intent.getStringExtra(MainActivity.EXTRA_PACKAGE)?.let(::scanInstalled)
        }
    }

    private fun launchBusy(block: suspend () -> Unit) {
        viewModelScope.launch {
            _state.update { it.copy(busy = true) }
            try { block() } finally { _state.update { it.copy(busy = false) } }
        }
    }
}
