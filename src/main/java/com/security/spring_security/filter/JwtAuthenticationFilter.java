package com.security.spring_security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.security.spring_security.dto.SessionDetailsDto;
import com.security.spring_security.service.CustomUserDetailsService;
import com.security.spring_security.service.SessionService;
import com.security.spring_security.utils.JwtUtil;

import org.springframework.web.filter.OncePerRequestFilter;


@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;
    private final SessionService sessionService;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, CustomUserDetailsService userDetailsService, SessionService sessionService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.sessionService = sessionService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authorizationHeader = request.getHeader("Authorization");
        String username = null;
        String token = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            token = authorizationHeader.substring(7);
            username = jwtUtil.extractUsername(token);

            // Extract client IP address
            String clientIp = request.getRemoteAddr();
            String sessionId = request.getSession().getId();
            // Check if the token is blacklisted
            if (sessionService.isAccessTokenBlacklisted(sessionId)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Token is blacklisted.");
                return;
            }

            // Validate active session and IP address

            SessionDetailsDto sessionDetails = sessionService.getSessionDetails(sessionId);
            if (sessionDetails == null || !sessionDetails.getClientIp().equals(clientIp)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                 // Blacklist the token due to IP address mismatch
                sessionService.blacklistAccessToken(sessionId);
                response.getWriter().write("Token is blacklisted due to suspicious activity.");
                return;
            }
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (jwtUtil.validateToken(token, userDetails.getUsername())) {
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }
}