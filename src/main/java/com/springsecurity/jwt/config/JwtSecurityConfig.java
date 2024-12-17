package com.springsecurity.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class JwtSecurityConfig {

    @Bean
    public SecurityFilterChain jwtFilterChain(HttpSecurity http, CustomAuthenticationEntryPoint customAuthenticationEntryPoint, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        return http
                .securityMatcher("/jwt/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAfter(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/jwt/public/**").permitAll()
                        .requestMatchers("/jwt/user/**").hasRole("USER")
                        .requestMatchers("/jwt/admin/**").hasRole("ADMIN")
                        .requestMatchers("/jwt/token").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(handler -> handler
                        .authenticationEntryPoint(customAuthenticationEntryPoint))
                .build();
    }
}
