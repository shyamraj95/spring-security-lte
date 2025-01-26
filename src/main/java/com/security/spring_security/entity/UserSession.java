package com.security.spring_security.entity;

import java.util.Date;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@Entity
public class UserSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String ipAddress;
    private String clientUuid;
    private Date loginDate;
    private Date logoutDate;;
    private String clientBrowserDetails;
    private boolean isSessionActive;
    private boolean isSessionExpired;
}