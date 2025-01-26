package com.security.spring_security.dto;

import java.time.LocalDateTime;

public class RefreshTokenCacheDto {
    private String sessionId;         // Unique session ID
    private String clientIp;          // Client IP for the session
    private int tokenRotationCount;   // Rotation count for the refresh token
    private boolean tokenBlacklisted; // Flag to indicate if the refresh token is blacklisted
    private LocalDateTime createdAt;  // Token creation timestamp

    public RefreshTokenCacheDto(String sessionId, String clientIp) {
        this.sessionId = sessionId;
        this.clientIp = clientIp;
        this.tokenRotationCount = 0;  // Initialize rotation count
        this.tokenBlacklisted = false;
        this.createdAt = LocalDateTime.now();
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getClientIp() {
        return clientIp;
    }

    public int getTokenRotationCount() {
        return tokenRotationCount;
    }

    public void incrementTokenRotationCount() {
        this.tokenRotationCount++;
    }

    public boolean isTokenBlacklisted() {
        return tokenBlacklisted;
    }

    public void setTokenBlacklisted(boolean tokenBlacklisted) {
        this.tokenBlacklisted = tokenBlacklisted;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
}
