package com.security.spring_security.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import com.security.spring_security.entity.UserEntity;
import com.security.spring_security.repository.UserRepository;
import com.security.spring_security.entity.Role;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String pfId) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByPfId(pfId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + pfId));
        return User
        .withUsername(user.getUsername())
        .password(user.getPassword())
        .roles(user.getRoles().stream().map(Role::getName).toArray(String[]::new))
        .build();
    }
}