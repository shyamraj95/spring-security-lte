package com.security.spring_security.service;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.security.spring_security.dto.RefreshTokenCacheDto;
import com.security.spring_security.dto.SessionDetailsDto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class SessionServiceImpl implements SessionService {
    @Value("${security.allowed-rotate-token-count}")
    private int allowedRotateTokenCount;

    private final Cache<String, SessionDetailsDto> activeSessions; // Cache for access tokens
    private final Cache<String, RefreshTokenCacheDto> refreshTokenCache; // Cache for refresh tokens

    public SessionServiceImpl(
            @Value("${security.jwt-access-token-expiration}") long accessTokenExpirationMs,
            @Value("${security.jwt-refresh-token-expiration}") long refreshTokenExpirationMs) {

        // Cache for access tokens (SessionDetails)
        this.activeSessions = CacheBuilder.newBuilder()
                .expireAfterWrite(accessTokenExpirationMs, TimeUnit.MILLISECONDS)
                .maximumSize(1000) // Optional: Limit cache size
                .build();

        // Cache for refresh tokens (mapped to session ID)
        this.refreshTokenCache = CacheBuilder.newBuilder()
                .expireAfterWrite(refreshTokenExpirationMs, TimeUnit.MILLISECONDS)
                .maximumSize(1000) // Optional: Limit cache size
                .build();
    }

    // Add session to activeSessions cache
    @Override
    public void addSession(String sessionId, String username, String clientIp) {
        SessionDetailsDto sessionDetails = new SessionDetailsDto(sessionId, username, clientIp, false);
        activeSessions.put(sessionId, sessionDetails);
    }

    // Add refresh token to refreshTokens cache
    @Override
    public void addRefreshToken(String sessionId, String refreshToken) {
        RefreshTokenCacheDto refreshTokenDetails = new RefreshTokenCacheDto(sessionId, refreshToken);
        refreshTokenCache.put(sessionId, refreshTokenDetails);
    }

    // Get session details by access token
    @Override
    public SessionDetailsDto getSessionDetails(String sessionId) {
        return activeSessions.getIfPresent(sessionId);
    }

    // Get refresh token details by refreshToken
    @Override
    public RefreshTokenCacheDto getRefreshTokenDetails(String refreshToken) {
        return refreshTokenCache.getIfPresent(refreshToken);
    }

    @Override
    public boolean validateRefreshTokenSource(String refreshToken, String clientIp) {
        RefreshTokenCacheDto refreshTokenDetails = refreshTokenCache.getIfPresent(refreshToken);
        if (refreshTokenDetails != null) {
            boolean isValidSource = refreshTokenDetails.getClientIp().equals(clientIp);
            if (isValidSource) {
                return true;
            }
            // if the clientIp suspicious will token blocked
            blacklistRefreshToken(refreshToken);
            return false;
        } else {
            return false;
        }
    }

    // Blacklist access token
    @Override
    public void blacklistAccessToken(String sessionId) {
        SessionDetailsDto sessionDetails = activeSessions.getIfPresent(sessionId);
        if (sessionDetails != null) {
            sessionDetails.setAccessTokenBlacklisted(true);
        }
    }

    // Blacklist refresh token
    @Override
    public void blacklistRefreshToken(String refreshToken) {
        RefreshTokenCacheDto refreshTokenDetails = refreshTokenCache.getIfPresent(refreshToken);
        if (refreshTokenDetails != null) {
            refreshTokenDetails.setTokenBlacklisted(true);
        }
    }

    // Increment refresh token rotation count
    @Override
    public void incrementRefreshTokenRotationCount(String refreshToken) {
        RefreshTokenCacheDto refreshTokenDetails = refreshTokenCache.getIfPresent(refreshToken);
        if (refreshTokenDetails != null) {
            refreshTokenDetails.incrementTokenRotationCount();
            if (refreshTokenDetails.getTokenRotationCount() > allowedRotateTokenCount) {
                // Block session if rotation count exceeds 3
                blacklistRefreshToken(refreshToken);
                refreshTokenCache.invalidate(refreshToken);
            }
        }
    }

    @Override
    public boolean isRefreshTokenBlacklisted(String refreshToken) {
        RefreshTokenCacheDto refreshTokenDetails = refreshTokenCache.getIfPresent(refreshToken);
        if (refreshTokenDetails != null) {
            return refreshTokenDetails.isTokenBlacklisted();
        }
        return true;
    }

    @Override
    public boolean isAccessTokenBlacklisted(String sessionId) {
        SessionDetailsDto sessionDetails = activeSessions.getIfPresent(sessionId);
        if (sessionDetails != null) {
            return sessionDetails.isAccessTokenBlacklisted();
        }
        return true;
    }

    @Override
    public void removeSession(String sessionId) {
        activeSessions.invalidate(sessionId);
    }

    @Override
    public void removeRefreshToken(String refreshToken) {
        refreshTokenCache.invalidate(refreshToken);
    }
}