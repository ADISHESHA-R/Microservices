package com.elearn.authentication.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    private final Key accessKey;
    private final Key refreshKey;
    private final long accessExpMs;
    private final long refreshExpMs;

    public JwtUtil(
            @Value("${jwt.access-secret}") String accessSecret,
            @Value("${jwt.refresh-secret}") String refreshSecret,
            @Value("${jwt.access-exp-ms}") long accessExpMs,
            @Value("${jwt.refresh-exp-ms}") long refreshExpMs) {
        this.accessKey = Keys.hmacShaKeyFor(accessSecret.getBytes());
        this.refreshKey = Keys.hmacShaKeyFor(refreshSecret.getBytes());
        this.accessExpMs = accessExpMs;
        this.refreshExpMs = refreshExpMs;
    }

    public String generateAccessToken(String userId, String username, String role) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(userId)
                .claim("username", username)
                .claim("role", role)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + accessExpMs))
                .signWith(accessKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(String userId) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + refreshExpMs))
                .signWith(refreshKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public Jws<Claims> parseAccessToken(String token) {
        return Jwts.parserBuilder().setSigningKey(accessKey).build().parseClaimsJws(token);
    }

    public Jws<Claims> parseRefreshToken(String token) {
        return Jwts.parserBuilder().setSigningKey(refreshKey).build().parseClaimsJws(token);
    }
}
