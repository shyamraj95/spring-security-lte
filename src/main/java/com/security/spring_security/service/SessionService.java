package com.security.spring_security.service;

import com.security.spring_security.dto.RefreshTokenCacheDto;
import com.security.spring_security.dto.SessionDetailsDto;

public interface SessionService {

    void addSession(String sessionId, String username, String clientIp, String accessToken);

    void addRefreshToken(String sessionId, String clientIp);

    SessionDetailsDto getSessionDetails(String sessionId);

    RefreshTokenCacheDto getRefreshTokenDetails(String sessionId);

    void blacklistAccessToken(String sessionId);

    void removeSession(String sessionId);

    boolean isRefreshTokenBlacklisted(String token);

    boolean isAccessTokenBlacklisted(String sessionId);

    void blacklistRefreshToken(String token);

    void incrementRefreshTokenRotationCount(String sessionId);

    public void removeRefreshToken(String sessionId);

}