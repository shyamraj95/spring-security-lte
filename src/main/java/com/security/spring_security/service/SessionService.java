package com.security.spring_security.service;

import com.security.spring_security.dto.RefreshTokenCacheDto;
import com.security.spring_security.dto.SessionDetailsDto;

public interface SessionService {

    void addSession(String sessionId, String username, String clientIp);

    void addRefreshToken(String refreshToken, String clientIp);

    SessionDetailsDto getSessionDetails(String sessionId);

    RefreshTokenCacheDto getRefreshTokenDetails(String sessionId);

    boolean validateRefreshTokenSource(String refreshToken, String clientIp);

    void blacklistAccessToken(String sessionId);

    void removeSession(String sessionId);

    boolean isRefreshTokenBlacklisted(String refreshToken);

    boolean isAccessTokenBlacklisted(String sessionId);

    void blacklistRefreshToken(String refreshToken);

    void incrementRefreshTokenRotationCount(String refreshToken);

    public void removeRefreshToken(String refreshToken);

}