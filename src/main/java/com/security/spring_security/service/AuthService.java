package com.security.spring_security.service;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import com.security.spring_security.dto.AuthRequest;
import com.security.spring_security.dto.registerUserDto;

public interface AuthService {
    Map<String, String> login( AuthRequest authRequest, HttpServletRequest request);

    void logout(String token, HttpServletRequest request);

    void registerUser(registerUserDto registerRequest);
    
    String refreshAccessToken(String refreshToken, HttpServletRequest request);
}