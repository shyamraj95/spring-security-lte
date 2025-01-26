package com.security.spring_security.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.spring_security.entity.UserSession;

public interface SessionRepository extends JpaRepository<UserSession, Long> {
    Optional<UserSession> findByUsername(String username);

    List<UserSession> findAllByUsernameAndIsSessionActive(String username, boolean isSessionActive);
}