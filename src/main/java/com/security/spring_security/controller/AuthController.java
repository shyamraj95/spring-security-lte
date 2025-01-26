package com.security.spring_security.controller;


import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.security.spring_security.dto.AuthRequest;
import com.security.spring_security.dto.registerUserDto;
import com.security.spring_security.service.AuthService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")

public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody registerUserDto registerRequest) {
        authService.registerUser(registerRequest);
        return ResponseEntity.ok("User registered successfully.");
    }
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest, HttpServletRequest request, HttpServletResponse response) {
        Map<String, String> tokens = authService.login(authRequest, request);
                // Set access token in response header
                response.setHeader("access_token", tokens.get("accessToken"));
                response.setHeader("refresh_token", tokens.get("refreshToken"));
        return ResponseEntity.ok("login Success");
    }

@PostMapping("/refresh")
public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
    String refreshToken = request.getHeader("refresh_token");

    try {
        // Generate a new access token
        String newAccessToken = authService.refreshAccessToken(refreshToken, request);

        // Set the new access token in the response header
        response.setHeader("Authorization", "Bearer " + newAccessToken);

        return ResponseEntity.ok("Access token refreshed successfully.");
    } catch (RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getMessage());
    }
}
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            authService.logout(token, request);
            return ResponseEntity.ok("Logged out and token blacklisted.");
        }
        return ResponseEntity.badRequest().body("No token found.");
    }
}