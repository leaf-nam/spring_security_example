package com.springsecurity.jwt.config;

import com.springsecurity.jwt.api.JwtApiController;
import com.springsecurity.jwt.api.JwtApiControllerV2;
import com.springsecurity.jwt.utility.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Configuration
@Import({JwtApiControllerV2.class, JwtApiController.class, JwtUtil.class, JwtAuthenticationFilter.class, CustomAuthenticationEntryPoint.class})
public class IntegrationTestConfig {

    @Bean(name = "mvcHandlerMappingIntrospector")
    public HandlerMappingIntrospector mvcHandlerMappingIntrospector() {
        return new HandlerMappingIntrospector();
    }

    @Bean(autowireCandidate = false)
    public static RoleHierarchy testRoleHierarchy() {
        return RoleHierarchyImpl.withDefaultRolePrefix()
                .role("ADMIN").implies("USER")
                .build();
    }
}
