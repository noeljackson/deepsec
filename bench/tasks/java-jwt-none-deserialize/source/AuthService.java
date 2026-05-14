package com.example.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class AuthService {

    public Object restoreSessionVulnerable(byte[] bytes) throws Exception {
        var ois = new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(bytes));
        return ois.readObject();
    }

    public Object restoreSessionSafe(String json) throws Exception {
        return JsonParser.parse(json);
    }

    public String verifyTokenVulnerable(String token) {
        return JWT.require(Algorithm.none()).build().verify(token).getSubject();
    }

    public String verifyTokenSafe(String token, String secret) {
        return JWT.require(Algorithm.HMAC256(secret)).build().verify(token).getSubject();
    }

    static class JsonParser { static Object parse(String s) { return s; } }
}
