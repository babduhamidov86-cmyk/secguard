package uz.secguard.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import uz.secguard.BuildConfig
import uz.secguard.core.RiskLevel
import uz.secguard.core.RiskReport
import uz.secguard.core.UrlGuard

private fun RiskLevel.color() = when (this) {
    RiskLevel.LOW -> Color(0xFF2E7D32)
    RiskLevel.MEDIUM -> Color(0xFFF9A825)
    RiskLevel.HIGH -> Color(0xFFEF6C00)
    RiskLevel.CRITICAL -> Color(0xFFC62828)
}

private fun UrlGuard.Verdict.color() = when (this) {
    UrlGuard.Verdict.SAFE -> Color(0xFF2E7D32)
    UrlGuard.Verdict.SUSPICIOUS -> Color(0xFFF9A825)
    UrlGuard.Verdict.DANGEROUS -> Color(0xFFC62828)
}

/** Birinchi ishga tushirishda ko'rsatiladigan shaffoflik va rozilik ekrani (Play siyosati: Prominent Disclosure). */
@Composable
fun ConsentScreen(onAccept: (serverLookup: Boolean, apkUpload: Boolean) -> Unit, onDecline: () -> Unit) {
    var server by rememberSaveable { mutableStateOf(false) }
    var upload by rememberSaveable { mutableStateOf(false) }
    val uri = LocalUriHandler.current

    Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("SecGuard — xavfsizlik yordamchisi", style = MaterialTheme.typography.headlineSmall)
        Section("Ilova nima qiladi", "• Yangi o'rnatilgan ilovalarning ruxsatlari va imzosini telefoningizning o'zida tekshiradi.\n" +
            "• Siz tanlagan yoki ulashgan APK faylni va havolalarni (masalan, Telegram'dan) tekshiradi.\n" +
            "• Shubhali holatda sizni ogohlantiradi. O'chirishni faqat siz tasdiqlaysiz.")
        Section("Qanday ma'lumot ishlatiladi", "• Tekshiruv sukut bo'yicha FAQAT qurilmada bajariladi.\n" +
            "• Xavfli fayllar/domenlar ro'yxati serverdan yuklab olinadi (sizning ma'lumotingiz yuborilmaydi).\n" +
            "• Quyidagi ixtiyoriy bandlarni yoqsangizgina server bilan ma'lumot almashiladi.")
        Section("Yig'ilmaydi", "SMS, kontaktlar, parollar, karta ma'lumotlari, shaxsiy fayllar va ekran mazmuni " +
            "o'qilmaydi. Accessibility xizmati ishlatilmaydi. Barcha fayllarni skanerlash yo'q: faqat siz tanlagan APK va o'rnatilgan ilovalar.")

        Row(verticalAlignment = Alignment.Top) {
            Checkbox(checked = server, onCheckedChange = { server = it })
            Text("Ixtiyoriy: server tekshiruvi. Faqat APK'ning SHA-256 xeshi va tekshirilayotgan havola matni yuboriladi.")
        }
        Row(verticalAlignment = Alignment.Top) {
            Checkbox(checked = upload, onCheckedChange = { upload = it })
            Text("Ixtiyoriy: chuqur tahlil uchun tanlagan APK faylni serverga yuklash. Fayl tahlildan keyin o'chiriladi, faqat xesh va natija saqlanadi.")
        }
        TextButton(onClick = { uri.openUri(BuildConfig.PRIVACY_POLICY_URL) }) { Text("Maxfiylik siyosatini o'qish") }

        Button(onClick = { onAccept(server, upload) }, modifier = Modifier.fillMaxWidth()) { Text("Tushundim, rozilik beraman") }
        OutlinedButton(onClick = onDecline, modifier = Modifier.fillMaxWidth()) { Text("Rad etish va chiqish") }
    }
}

@Composable
private fun Section(title: String, body: String) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title, fontWeight = FontWeight.SemiBold)
            Text(body, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
fun HomeScreen(
    state: UiState,
    onMonitorToggle: (Boolean) -> Unit,
    onUrlChange: (String) -> Unit,
    onCheckUrl: () -> Unit,
    onPickApk: () -> Unit,
    onSync: () -> Unit,
    onRevoke: () -> Unit,
) {
    val uri = LocalUriHandler.current
    Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("SecGuard", style = MaterialTheme.typography.headlineSmall)
        if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        state.message?.let { Text(it, color = MaterialTheme.colorScheme.primary) }

        Card(Modifier.fillMaxWidth()) {
            Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Yangi ilovalar monitori", fontWeight = FontWeight.SemiBold)
                    Text("Ilova o'rnatilgach darhol tekshiradi (bildirishnoma ko'rinib turadi).", style = MaterialTheme.typography.bodySmall)
                }
                Switch(checked = state.monitorEnabled, onCheckedChange = onMonitorToggle)
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Havolani tekshirish", fontWeight = FontWeight.SemiBold)
                OutlinedTextField(
                    value = state.urlInput, onValueChange = onUrlChange, modifier = Modifier.fillMaxWidth(),
                    label = { Text("URL yoki Telegram havola") }, singleLine = true,
                )
                Button(onClick = onCheckUrl, enabled = !state.busy) { Text("Tekshirish") }
                state.urlResult?.let { UrlResultView(it) }
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("APK faylni tekshirish", fontWeight = FontWeight.SemiBold)
                Text("O'rnatishdan OLDIN faylni tanlab tekshiring. Fayl ishga tushirilmaydi.", style = MaterialTheme.typography.bodySmall)
                Button(onClick = onPickApk, enabled = !state.busy) { Text("APK tanlash") }
                state.report?.let { ReportView(it) }
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Qora ro'yxat: ${state.blacklistCount} yozuv", Modifier.weight(1f))
            TextButton(onClick = onSync, enabled = !state.busy) { Text("Yangilash") }
        }
        TextButton(onClick = { uri.openUri(BuildConfig.PRIVACY_POLICY_URL) }) { Text("Maxfiylik siyosati") }
        OutlinedButton(onClick = onRevoke, modifier = Modifier.fillMaxWidth()) { Text("Rozilikni bekor qilish va ma'lumotlarni o'chirish") }
    }
}

@Composable
private fun UrlResultView(r: UrlGuard.Result) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("${r.verdict}  •  ${r.score}%", color = r.verdict.color(), fontWeight = FontWeight.Bold)
        r.reasons.forEach { Text("• ${it.text}", style = MaterialTheme.typography.bodySmall) }
        if (r.reasons.isEmpty()) Text("Shubhali belgilar topilmadi. Bu 100% xavfsizlik kafolati emas.", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun ReportView(r: RiskReport) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(r.appName ?: r.packageName ?: "Noma'lum", fontWeight = FontWeight.SemiBold)
        r.packageName?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        Text("Xavf: ${r.score}%  (${r.level})", color = r.level.color(), fontWeight = FontWeight.Bold)
        LinearProgressIndicator(progress = { r.score / 100f }, color = r.level.color(), modifier = Modifier.fillMaxWidth())
        r.sha256?.let { Text("SHA-256: ${it.take(16)}…", style = MaterialTheme.typography.bodySmall) }
        r.reasons.take(8).forEach { Text("• ${it.text} (+${it.points})", style = MaterialTheme.typography.bodySmall) }
    }
}
