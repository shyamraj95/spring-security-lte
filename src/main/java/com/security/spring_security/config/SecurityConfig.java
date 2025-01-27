package com.security.spring_security.config;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.security.spring_security.exception.CustomAccessDeniedHandler;
import com.security.spring_security.filter.JwtAuthenticationFilter;
import com.security.spring_security.service.CustomUserDetailsService;

@Configuration
public class SecurityConfig {
    private final String[] publicEndpoints = {
            "/api/auth/**",
            "/error/**",
            "/resources/**",
            "/h2-console/**"
    };

    @Value("${security.enable-ldap}") // Flag to enable or disable LDAP
    private boolean enableLdap;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomUserDetailsService customUserDetailsService;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
            CustomUserDetailsService customUserDetailsService,
            CustomAccessDeniedHandler customAccessDeniedHandler) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.customUserDetailsService = customUserDetailsService;
        this.customAccessDeniedHandler = customAccessDeniedHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeRequests(requests -> requests
                        .antMatchers(publicEndpoints).permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(
                        exceptionHandling -> exceptionHandling.accessDeniedHandler(customAccessDeniedHandler))
                .sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .headers(headers ->
                // headers.frameOptions().disable()
                headers.frameOptions().sameOrigin()
                        .contentSecurityPolicy("frame-ancestors 'self' http://localhost:8080/h2-console/**;"));

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
     * @Bean
     * 
     * @ConditionalOnProperty(name = "security.enable-ldap", havingValue = "true")
     * public AuthenticationProvider ldapAuthenticationProvider() {
     * ActiveDirectoryLdapAuthenticationProvider provider =
     * new ActiveDirectoryLdapAuthenticationProvider("www.forumsys.com",
     * "ldap://ldap.forumsys.com:389");
     * provider.setUseAuthenticationRequestCredentials(true);
     * return provider;
     * }
     */
    // Define the LDAP context source
    @Bean
    @ConditionalOnProperty(name = "security.enable-ldap", havingValue = "true")
    public DefaultSpringSecurityContextSource contextSource() {
        DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
                Collections.singletonList("ldap://ldap.forumsys.com:389"), // LDAP server
                "dc=example,dc=com" // Base DN
        );
        contextSource.setUserDn("cn=read-only-admin,dc=example,dc=com"); // Bind DN
        contextSource.setPassword("password"); // Bind password
        return contextSource;
    }

    @Bean
    @ConditionalOnProperty(name = "security.enable-ldap", havingValue = "true")
    public AuthenticationProvider ldapAuthenticationProvider(DefaultSpringSecurityContextSource contextSource) {
        // Configure Bind Authenticator
        BindAuthenticator authenticator = new BindAuthenticator(contextSource);
        authenticator.setUserDnPatterns(new String[] {
                "uid={0},ou=mathematicians,dc=example,dc=com",
                "uid={0},ou=scientists,dc=example,dc=com"
        });

        // Configure Authorities Populator
        DefaultLdapAuthoritiesPopulator authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(contextSource,
                "dc=example,dc=com"); // Base for groups
        authoritiesPopulator.setGroupSearchFilter("(uniqueMember=uid={0},dc=example,dc=com)"); // Group search filter
        authoritiesPopulator.setSearchSubtree(true); // Search groups in subtrees

        return new LdapAuthenticationProvider(authenticator, authoritiesPopulator);
    }

    public void configure(AuthenticationManagerBuilder auth, AuthenticationProvider ldapAuthenticationProvider)
            throws Exception {
        if (isLdapBeanPresent()) {
            auth.authenticationProvider(ldapAuthenticationProvider); // LDAP Authentication
        }
        auth.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder()); // Database fallback
    }

    private boolean isLdapBeanPresent() {
        return enableLdap;
    }

    /*
     * @Bean
     * public RoleVoter roleVoter() {
     * RoleVoter roleVoter = new RoleVoter();
     * roleVoter.setRolePrefix(""); // Remove "ROLE_" prefix requirement
     * return roleVoter;
     * }
     */

}

/*
 * test commands
 * ldapsearch -x -H ldap://ldap.forumsys.com -D
 * "uid=riemann,ou=mathematicians,dc=example,dc=com" -w password \ -b
 * "dc=example,dc=com" "(objectClass=*)"
 * 
 * ldapsearch -x -H ldap://ldap.forumsys.com -D
 * "cn=read-only-admin,dc=example,dc=com" -w password -b "dc=example,dc=com"
 * "(objectClass=*)"
 * 
 * ldapsearch -W -h ldap.forumsys.com -D "uid=tesla,dc=example,dc=com" -b
 * "dc=example,dc=com"
 * 
 * http://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-
 * server/
 */