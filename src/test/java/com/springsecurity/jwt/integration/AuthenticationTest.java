package com.springsecurity.jwt.integration;

import com.springsecurity.jwt.api.ApiController;
import com.springsecurity.jwt.config.SecurityConfig;
import com.springsecurity.jwt.config.IntegrationTestConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = SecurityConfig.class)
@WebAppConfiguration
@Import({ApiController.class, IntegrationTestConfig.class})
class AuthenticationTest {

    MockMvc mockMvc;

    @Autowired
    WebApplicationContext context;

    @BeforeEach
    void init() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity()).build();
    }

    @Test
    @DisplayName("권한이 없는 사용자가 인증이 필요한 요청 시 401 응답(인증 오류)")
    void testAuthenticationError() throws Exception {
        mockMvc.perform(get("/user/resources"))
                .andExpect(status().is(401));
    }

    @Test
    @DisplayName(" 권한이 부족한 사용자가 상위 권한의 요청 시 403 응답(인가 오류)")
    void testAuthorizationError() throws Exception {
        mockMvc.perform(get("/admin/resources").with(user("user").roles("USER")))
                .andExpect(status().is(403));
    }

    @Test
    @DisplayName("적절한 권한이 있는 사용자는 인증이 필요한 요청 시 200 응답(Happy Case)")
    void testHappyCase() throws Exception {

        // 권한 없는 사용자 -> Public API
        mockMvc.perform(get("/public/resources"))
                .andExpect(status().is(200));

        // User -> User API
        mockMvc.perform(get("/user/resources").with(user("user").roles("USER")))
                .andExpect(status().is(200));

        // Admin -> User API
        mockMvc.perform(get("/user/resources").with(user("admin").roles("ADMIN")))
                .andExpect(status().is(200));

        // Admin -> Admin API
        mockMvc.perform(get("/admin/resources").with(user("admin").roles("ADMIN")))
                .andDo(print())
                .andExpect(status().is(200));

    }
}