package com.security.spring_security.config;

import javax.validation.constraints.NotNull;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {
    @NotNull
    private String rsaPrivateKeyPath;
    @NotNull
    private String rsaPublicKeyPath;
    @NotNull
    private String jwtSecret;
    @NotNull
    private String jwtRefreshSecret;
    @NotNull
    private String jwtAccessTokenExpiration;
    @NotNull
    private String jwtRefreshTokenExpiration;
    @NotNull
    private boolean enableLdap;
    @NotNull
    private int allowedRotateTokenCount;

}

/* spring-boot-configuration-processor dependency is required */
