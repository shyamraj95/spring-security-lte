package com.security.spring_security.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;

@Component
public class JwtUtil {
    @Value("${security.jwt-secret}")
    private String secret;

    @Value("${security.jwt-access-token-expiration}")
    private long tokenExpiration;

    @Value("${security.jwt-refresh-secret}")
    private String refreshSecret;

    @Value("${security.jwt-refresh-token-expiration}")
    private long refreshExpiration;

    public String generateToken(String username, List<String> roles) throws JwtException {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);
        Instant now = Instant.now();
        Date issuedAt = Date.from(now);
        Date expiration = Date.from(now.plusSeconds(tokenExpiration* 60));
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()), SignatureAlgorithm.HS512)
                .compact();
    }

    // Generate Refresh Token
    public String generateRefreshToken(String username) throws JwtException {
        Instant now = Instant.now();
        Date issuedAt = Date.from(now);
        Date expiration = Date.from(now.plusSeconds(refreshExpiration * 60));
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .signWith(Keys.hmacShaKeyFor(refreshSecret.getBytes()), SignatureAlgorithm.HS512)
                .compact();
    }

    public String extractUsername(String token) throws JwtException {
        return Jwts.parserBuilder().setSigningKey(secret.getBytes()).build().parseClaimsJws(token).getBody()
                .getSubject();
    }

    public List<String> extractRoles(String token) {
        Object roles = Jwts.parserBuilder().setSigningKey(secret.getBytes()).build().parseClaimsJws(token).getBody()
                .get("roles");
        if (roles instanceof List<?>) {
            return ((List<?>) roles).stream()
                    .filter(role -> role instanceof String)
                    .map(role -> (String) role)
                    .collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    public String extractUsernameFromRefreshToken(String token) throws JwtException {
        return Jwts.parserBuilder().setSigningKey(refreshSecret.getBytes()).build().parseClaimsJws(token).getBody()
                .getSubject();
    }

    public boolean validateToken(String token, String username) throws JwtException {
        return username.equals(extractUsername(token)) && !isTokenExpired(token);
    }

    // Validate Refresh Token
    public boolean validateRefreshToken(String refreshToken, String username) throws JwtException {
        return username.equals(extractUsernameFromRefreshToken(refreshToken)) && !isRefreshTokenExpired(refreshToken);
    }

    private boolean isTokenExpired(String token) throws JwtException {
        return Jwts.parserBuilder().setSigningKey(secret.getBytes()).build().parseClaimsJws(token).getBody()
                .getExpiration().before(new Date());
    }

    private boolean isRefreshTokenExpired(String token) throws JwtException {
        return Jwts.parserBuilder().setSigningKey(refreshSecret.getBytes()).build().parseClaimsJws(token).getBody()
                .getExpiration().before(new Date());
    }
}