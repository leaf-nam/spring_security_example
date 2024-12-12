package com.springsecurity.jwt.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthenticationFilterTest {

    @Test
    @DisplayName("Bearer 제거 테스트")
    void testDeleteBearer() {
        String header = "Bearer test";
        String token = header.split("Bearer ")[1];
        assertThat(token).isEqualTo("test");
    }
}