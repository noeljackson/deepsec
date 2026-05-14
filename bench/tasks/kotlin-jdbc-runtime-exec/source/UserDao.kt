package com.example.app

import java.sql.Connection
import java.sql.Statement
import javax.sql.DataSource

class UserDao(private val ds: DataSource) {

    fun findVulnerable(name: String): String? {
        val c: Connection = ds.connection
        val stmt: Statement = c.createStatement()
        val rs = stmt.executeQuery("SELECT email FROM users WHERE name = '$name'")
        return if (rs.next()) rs.getString(1) else null
    }

    fun convertVulnerable(filename: String): Int {
        val p = Runtime.getRuntime().exec("convert $filename out.png")
        return p.waitFor()
    }

    fun convertSafe(filename: String): Int {
        val pb = ProcessBuilder("convert", filename, "out.png")
        val p = pb.start()
        return p.waitFor()
    }
}
