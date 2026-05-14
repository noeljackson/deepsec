package com.example.app;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.sql.DataSource;

public class UserController {
    private final DataSource ds;

    public UserController(DataSource ds) {
        this.ds = ds;
    }

    public ResultSet findVulnerable(String name) throws Exception {
        Connection c = ds.getConnection();
        Statement stmt = c.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public ResultSet findSafe(String name) throws Exception {
        Connection c = ds.getConnection();
        PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }

    public int runVulnerable(String filename) throws Exception {
        Process p = Runtime.getRuntime().exec("convert " + filename + " out.png");
        return p.waitFor();
    }

    public int runSafe(String filename) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("convert", filename, "out.png");
        Process p = pb.start();
        return p.waitFor();
    }
}
