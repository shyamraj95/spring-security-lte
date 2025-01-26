package com.security.spring_security.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class AuthRequest {
    private String pfId;
    private String password;
    private String uuid;
}

