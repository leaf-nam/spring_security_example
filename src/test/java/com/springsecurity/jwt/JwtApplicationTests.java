package com.springsecurity.jwt;

import com.springsecurity.jwt.config.JwtAuthenticationFilter;
import com.springsecurity.jwt.config.JwtAuthenticationProvider;
import com.springsecurity.jwt.config.SecurityConfig;
import com.springsecurity.jwt.config.IntegrationTestConfig;
import com.springsecurity.jwt.utility.JwtUtil;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(classes = {SecurityConfig.class, IntegrationTestConfig.class, JwtAuthenticationProvider.class, JwtAuthenticationFilter.class, JwtUtil.class})
class JwtApplicationTests {

	@Test
	void contextLoads() {
	}

}
