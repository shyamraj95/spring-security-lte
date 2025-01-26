package com.security.spring_security.service;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.stereotype.Service;

import com.security.spring_security.dto.AuthRequest;

import com.security.spring_security.dto.registerUserDto;
import com.security.spring_security.entity.Role;
import com.security.spring_security.entity.UserEntity;
import com.security.spring_security.repository.RoleRepository;
import com.security.spring_security.repository.UserRepository;
import com.security.spring_security.utils.JwtUtil;

@Service
public class AuthServiceImpl implements AuthService {
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final SessionService sessionService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailsService userDetailsService;

    public AuthServiceImpl(JwtUtil jwtUtil, AuthenticationManager authenticationManager,
            SessionService sessionService, UserRepository userRepository, RoleRepository roleRepository,
            PasswordEncoder passwordEncoder, CustomUserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.sessionService = sessionService;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Map<String, String> login(AuthRequest authRequest, HttpServletRequest request) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getPfId(), authRequest.getPassword()));
        } catch (Exception ex) {
            throw new RuntimeException("Authentication failed: " + ex.getMessage());
        }

        // Extract roles from the authenticated user's authorities
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        Map<String, String> response = new HashMap<>();
        // Generate JWT tokens
        String accessToken = jwtUtil.generateToken(authRequest.getPfId(), roles);
        String refreshToken = jwtUtil.generateRefreshToken(authRequest.getPfId());
        // Save session details
        String sessionId = request.getSession().getId();
        String clientIp = request.getRemoteAddr();
        sessionService.addSession(sessionId, authRequest.getPfId(), clientIp, refreshToken);
        response.put("accessToken", accessToken);
        response.put("refreshToken", refreshToken);
        return response;
    }

    @Override
    public String refreshAccessToken(String refreshToken, HttpServletRequest request) {
        // Check if the refresh token is blacklisted
        if (sessionService.isRefreshTokenBlacklisted(refreshToken)) {
            throw new RuntimeException("Refresh token is blacklisted or invalid.");
        }

        // Validate the refresh token
        String username = jwtUtil.extractUsernameFromRefreshToken(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (!jwtUtil.validateRefreshToken(refreshToken, userDetails.getUsername())) {
            throw new RuntimeException("Invalid or expired refresh token.");
        }

        // Get session details and increment the rotation count
        String sessionId = request.getSession().getId(); // Get session ID by refresh token
        boolean tokenDetails = sessionService.isRefreshTokenBlacklisted(sessionId);

        if (tokenDetails) {
            throw new RuntimeException("Refresh token is blacklisted or invalid.");
        }

        sessionService.incrementRefreshTokenRotationCount(sessionId);

        // Issue a new access token
        return jwtUtil.generateToken(userDetails.getUsername(), userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
    }

    @Override
    public void logout(String token, HttpServletRequest request) {
        String sessionId = request.getSession().getId();
        sessionService.removeRefreshToken(sessionId);
        // Remove session details
        sessionService.removeSession(sessionId);
    }

    @Override
    @Transactional
    public void registerUser(registerUserDto registerRequest) {
        // Check if the username already exists
        if (userRepository.findByPfId(registerRequest.getPfId()).isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }

        // Encode the password
        String encodedPassword = passwordEncoder.encode(registerRequest.getPassword());

        // Assign default role
        Role userRole = roleRepository.findByName("DEFAULT_ROLE")
                .orElseThrow(() -> new IllegalStateException("Default role DEFAULT_ROLE not found"));

        // Create and save the user
        UserEntity user = new UserEntity();
        user.setPfId(registerRequest.getPfId());
        user.setPassword(encodedPassword);
        user.setRoles(Collections.singleton(userRole));

        userRepository.save(user);
    }
}