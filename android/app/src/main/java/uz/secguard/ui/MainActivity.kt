package uz.secguard.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle

class MainActivity : ComponentActivity() {
    private val vm: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) vm.handleIntent(intent)
        setContent {
            MaterialTheme {
                Surface(Modifier.fillMaxSize()) { Root(vm, onFinish = { finish() }) }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        vm.handleIntent(intent)
    }

    companion object {
        const val EXTRA_PACKAGE = "uz.secguard.extra.PACKAGE"
    }
}

@Composable
private fun Root(vm: MainViewModel, onFinish: () -> Unit) {
    val state by vm.state.collectAsStateWithLifecycle()
    val ctx = LocalContext.current

    // Android 13+: bildirishnoma ruxsatisiz ogohlantirish ko'rinmaydi, shuning uchun monitorni faqat ruxsat bilan yoqamiz.
    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) vm.setMonitor(true)
    }
    val pickApk = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let(vm::scanApk)
    }

    if (!state.consented) {
        ConsentScreen(onAccept = vm::acceptConsent, onDecline = onFinish)
    } else {
        HomeScreen(
            state = state,
            onMonitorToggle = { on ->
                val needsPermission = on && Build.VERSION.SDK_INT >= 33 &&
                    ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                if (needsPermission) notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS) else vm.setMonitor(on)
            },
            onUrlChange = vm::onUrlChange,
            onCheckUrl = vm::checkUrl,
            onPickApk = { pickApk.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) },
            onSync = vm::syncNow,
            onRevoke = vm::revokeConsent,
        )
    }
}
