package uz.secguard.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import uz.secguard.core.BlacklistLookup

data class Indicator(val kind: String, val value: String, val severity: Int, val status: String)

/** Lokal qora ro'yxat (SQLite). Server bilan `SyncRepository` orqali inkremental sinxronlanadi. */
class BlacklistDb(context: Context) :
    SQLiteOpenHelper(context.applicationContext, "blacklist.db", null, 1), BlacklistLookup {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE indicators(" +
                "kind TEXT NOT NULL, value TEXT NOT NULL, severity INTEGER NOT NULL, " +
                "PRIMARY KEY(kind, value)) WITHOUT ROWID"
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS indicators")
        onCreate(db)
    }

    override fun contains(kind: String, value: String): Boolean =
        readableDatabase.rawQuery(
            "SELECT 1 FROM indicators WHERE kind = ? AND value = ? LIMIT 1",
            arrayOf(kind, value.lowercase()),
        ).use { it.moveToFirst() }

    /** 'revoked' yozuvlar o'chiriladi, qolganlari yoziladi/yangilanadi. Bitta tranzaksiyada. */
    fun applyChanges(items: List<Indicator>) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            for (i in items) {
                val value = i.value.lowercase()
                if (i.status == "revoked") {
                    db.delete("indicators", "kind = ? AND value = ?", arrayOf(i.kind, value))
                } else {
                    val cv = ContentValues().apply {
                        put("kind", i.kind); put("value", value); put("severity", i.severity)
                    }
                    db.insertWithOnConflict("indicators", null, cv, SQLiteDatabase.CONFLICT_REPLACE)
                }
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun count(): Int =
        readableDatabase.rawQuery("SELECT COUNT(*) FROM indicators", null).use { if (it.moveToFirst()) it.getInt(0) else 0 }

    fun clear() { writableDatabase.delete("indicators", null, null) }
}
