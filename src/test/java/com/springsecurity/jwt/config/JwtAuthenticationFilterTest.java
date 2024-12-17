package com.springsecurity.jwt.config;

import com.springsecurity.jwt.utility.JwtUtil;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthenticationFilterTest {

    @Test
    @DisplayName("Bearer 제거 테스트")
    void testDeleteBearer() {
        String header = "Bearer test";
        String token = header.split("Bearer ")[1];
        assertThat(token).isEqualTo("test");
    }

    @Test
    @DisplayName("Bearer 파싱 테스트")
    void testDeleteBearer2() throws ServletException, IOException {
        // given
        JwtUtil jwtUtil = new JwtUtil();
        JwtAuthenticationFilter suit = new JwtAuthenticationFilter(jwtUtil);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + jwtUtil.issue("user", "USER"));

        // when
        suit.doFilterInternal(request, new MockHttpServletResponse(), new MockFilterChain());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // then
        assertThat(authentication.getAuthorities()).anySatisfy(auth -> assertThat(auth.getAuthority()).isEqualTo("ROLE_USER"));
    }
}