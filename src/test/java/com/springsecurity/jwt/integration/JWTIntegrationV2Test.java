package com.springsecurity.jwt.integration;

import com.springsecurity.jwt.config.IntegrationTestConfig;
import com.springsecurity.jwt.config.JwtSecurityConfigV2;
import com.springsecurity.jwt.utility.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = JwtSecurityConfigV2.class)
@WebAppConfiguration
@Import(IntegrationTestConfig.class)
public class JWTIntegrationV2Test {

    MockMvc mockMvc;
    JwtUtil jwtUtil;

    @Autowired
    WebApplicationContext context;

    @BeforeEach
    void init() {
        jwtUtil = new JwtUtil();
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity()).build();
    }

    @Test
    @DisplayName("1. 로그인 실패 시 jwt를 발행하지 않는다.")
    void testLoginFailure() throws Exception {
        // given : 정상 아이디와 잘못된 패스워드(user)
        String id = "user";
        String password = "badPassword";

        // when : 토큰 발급 시도
        mockMvc.perform(post("/jwt/v2/token")
                        .param("username", id)
                        .param("password", password))
                .andDo(print())

                // then : 401(Unauthenticated) 오류
                .andExpect(status().is(401));

        // given : 정상 아이디와 잘못된 패스워드(admin)
        id = "admin";
        password = "badPassword";

        // when : 토큰 발급 시도
        mockMvc.perform(post("/jwt/v2/token")
                        .param("username", id)
                        .param("password", password))
                .andDo(print())

                // then : 401(Unauthenticated) 오류
                .andExpect(status().is(401));
    }

    @Test
    @DisplayName("2. 정상 로그인 시 jwt를 발행한다.(Happy Case)")
    void testLoginSuccess() throws Exception {
        // given : 정상 아이디, 패스워드
        String id = "user";
        String password = "user1234";

        // when : 토큰 발급
        String token = mockMvc.perform(post("/jwt/v2/token")
                        .param("username", id)
                        .param("password", password))
                .andExpect(status().is(200))
                .andReturn().getResponse().getContentAsString();

        // then : 정상 토큰여부 확인(JwtUtil)
        jwtUtil.validate(token);
    }

    @Test
    @DisplayName("3. 잘못된 jwt로 인증할 수 없다.")
    void testAuthentication() throws Exception {
        // given : 잘못된 jwt 토큰
        String badToken = "bearer asdf1234";

        // when : User API 접근
        mockMvc.perform(get("/jwt/v2/user/resources")
                        .header(HttpHeaders.AUTHORIZATION, badToken))

                // then : 401 오류
                .andExpect(status().is(401));
    }

    @Test
    @DisplayName("4. 권한이 부족한 jwt에 인가할 수 없다.")
    void testAuthorization() throws Exception {
        // given : User JWT 획득
        String id = "user";
        String password = "user1234";
        String userToken = mockMvc.perform(post("/jwt/v2/token")
                        .param("username", id)
                        .param("password", password))
                .andExpect(status().is(200))
                .andReturn().getResponse().getContentAsString();

        // when : Admin API 접근
        mockMvc.perform(get("/jwt/v2/admin/resources")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken))

                // then : 403(Forbidden) 오류
                .andExpect(status().is(403));
    }

    @Test
    @DisplayName("5. 정상적인 jwt로 특정 권한의 api를 사용할 수 있다.`(Happy Case)`")
    void testHappyCase() throws Exception {
        // given : Admin JWT 획득
        String id = "admin";
        String password = "admin1234";
        String adminToken = mockMvc.perform(post("/jwt/v2/token")
                        .param("username", id)
                        .param("password", password))
                .andExpect(status().is(200))
                .andReturn().getResponse().getContentAsString();

        // when : 권한 없이 PUBLIC API 접근
        mockMvc.perform(get("/jwt/v2/public/resources")
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().is(200))

                // then : Public 자원 획득
                .andExpect(content().encoding(StandardCharsets.UTF_8))
                .andExpect(content().string("PUBLIC 자원 획득"));

        // when : Admin 권한으로 USER API 접근
        mockMvc.perform(get("/jwt/v2/user/resources")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())

                // then : User 자원 획득
                .andExpect(status().is(200))
                .andExpect(content().encoding(StandardCharsets.UTF_8))
                .andExpect(content().string("USER 자원 획득"));

        // when : Admin 권한으로 Admin API 접근
        mockMvc.perform(get("/jwt/v2/admin/resources")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .accept(MediaType.APPLICATION_JSON))

                // then : Admin 자원 획득
                .andExpect(status().is(200))
                .andExpect(content().encoding(StandardCharsets.UTF_8))
                .andExpect(content().string("ADMIN 자원 획득"));
    }
}
