package com.security.spring_security.dto;

import java.time.LocalDateTime;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SessionDetailsDto {
    private String sessionId;
    private String username;
    private String clientIp;
    private boolean accessTokenBlacklisted;
    private LocalDateTime createdAt;

    public SessionDetailsDto(String sessionId, String username, String clientIp, boolean accessTokenBlacklisted) {
        this.sessionId = sessionId;
        this.username = username;
        this.clientIp = clientIp;
        this.accessTokenBlacklisted = accessTokenBlacklisted;
        this.createdAt = LocalDateTime.now();
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
