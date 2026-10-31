package uz.secguard.data

import org.json.JSONObject
import uz.secguard.BuildConfig
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** Backend REST klienti (faqat HTTPS). Tashqi kutubxonasiz: HttpURLConnection + org.json. */
class ApiClient(
    private val baseUrl: String = BuildConfig.API_BASE_URL,
    private val apiKey: String = BuildConfig.API_KEY,
) {
    data class SyncPage(val serverTime: Long, val nextSince: Long, val hasMore: Boolean, val items: List<Indicator>)

    /** Bloklovchi chaqiruvlar: IO oqimida ishlating. */
    fun syncPage(since: Long): SyncPage {
        val j = json(open("GET", "/v1/blacklist/sync?since=$since"))
        val arr = j.getJSONArray("items")
        val items = List(arr.length()) {
            val o = arr.getJSONObject(it)
            Indicator(o.getString("kind"), o.getString("value"), o.optInt("severity", 80), o.getString("status"))
        }
        return SyncPage(j.getLong("server_time"), j.getLong("next_since"), j.getBoolean("has_more"), items)
    }

    /** Foydalanuvchi roziligi bilan: faqat SHA-256 yuboriladi. */
    fun lookupHash(sha256: String): Boolean =
        json(post("/v1/lookup/hash", JSONObject().put("sha256", sha256))).getBoolean("blacklisted")

    /** Foydalanuvchi roziligi bilan: havola matni yuboriladi. */
    fun checkUrl(url: String): JSONObject = json(post("/v1/url/check", JSONObject().put("url", url)))

    /** Foydalanuvchi roziligi bilan (alohida opt-in): APK chuqur tahlil uchun yuklanadi, server uni saqlamaydi. */
    fun uploadApk(file: File): JSONObject {
        val boundary = "----secguard${System.currentTimeMillis()}"
        val c = open("POST", "/v1/analyze/apk", readTimeoutMs = 120_000)
        c.doOutput = true
        c.setChunkedStreamingMode(0)
        c.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
        c.outputStream.use { out ->
            out.write(
                ("--$boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload.bin\"\r\n" +
                    "Content-Type: application/octet-stream\r\n\r\n").toByteArray()
            )
            file.inputStream().use { it.copyTo(out) }
            out.write("\r\n--$boundary--\r\n".toByteArray())
        }
        return json(c)
    }

    private fun post(path: String, body: JSONObject): HttpURLConnection {
        val c = open("POST", path)
        c.doOutput = true
        c.setRequestProperty("Content-Type", "application/json")
        c.outputStream.use { it.write(body.toString().toByteArray()) }
        return c
    }

    private fun open(method: String, path: String, readTimeoutMs: Int = 15_000): HttpURLConnection {
        require(baseUrl.startsWith("https://")) { "Faqat HTTPS qo'llab-quvvatlanadi" }
        val c = URL(baseUrl.trimEnd('/') + path).openConnection() as HttpURLConnection
        c.requestMethod = method
        c.connectTimeout = 10_000
        c.readTimeout = readTimeoutMs
        c.setRequestProperty("X-API-Key", apiKey)
        c.setRequestProperty("Accept", "application/json")
        return c
    }

    private fun json(c: HttpURLConnection): JSONObject {
        try {
            val code = c.responseCode
            if (code !in 200..299) throw IOException("HTTP $code")
            return JSONObject(c.inputStream.bufferedReader().use { it.readText() })
        } finally {
            c.disconnect()
        }
    }
}
