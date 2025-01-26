package com.security.spring_security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import com.security.spring_security.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByPfId(String pfId);

}