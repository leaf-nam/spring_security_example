package com.springsecurity.jwt.utility;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class JwtUtilTest {

    JwtUtil suit;

    // JWT 형식이 아닌 토큰
    String invalidToken1 = "INVALIDATE_TOKEN";

    // https://jwt.io 에서 만든 예제 토큰
    String invalidToken2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // sub : admin, role : admin 이지만 유효하지 않은 secret key 를 사용한 토큰
    String invalidToken3 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.wpTc_a19-bJNZ7oeYghAmxks3tk2mjcP6xTqYe2u86c";

    // sub : admin, role : ADMIN, 유효한 secret key 를 사용한 토큰
    String validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiJ9.VYYrrkyu4kmM4zWtl_gFk9leBM8xu-XxxIYUtY9_2n0";

    @BeforeEach
    void init() {
        suit = new JwtUtil();
    }

    @Test
    @DisplayName("1. 유효하지 않은 토큰 검증 시 런타임 오류를 반환한다.")
    void testInvalidateToken() {
        assertThatThrownBy(() -> suit.validate(invalidToken1))
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> suit.validate(invalidToken2))
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> suit.validate(invalidToken3))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("2. 유효한 토큰 검증 시 오류가 발생하지 않는다.(Happy Case)")
    void testValidateToken() {
        suit.validate(validToken);
    }

    @Test
    @DisplayName("3. 잘못된 권한의 토큰 발급 시 런타임 오류를 반환한다.")
    void testIllegalRoleIssue() {
        String userName = "test_user";
        String role = "ILLEGAL_ROLE";
        assertThatThrownBy(() -> suit.issue(userName, role))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("4. 사용자 권한별 정상적인 토큰을 발급한다.(Happy Case)")
    void testLegalRoleIssue() {
        // given
        String userName = "user";
        String userRole = "USER";
        String adminName = "admin";
        String adminRole = "ADMIN";

        // when
        String userToken = suit.issue(userName, userRole);
        String adminToken = suit.issue(adminName, adminRole);

        // then
        suit.validate(userToken);
        suit.validate(adminToken);
    }

    @Test
    @DisplayName("5. 유효하지 않은 토큰 파싱 시 런타임 오류를 반환한다.")
    void testIllegalTokenParse() {
        assertThatThrownBy(() -> suit.parseName(invalidToken1))
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> suit.parseName(invalidToken2))
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> suit.parseName(invalidToken3))
                .isInstanceOf(RuntimeException.class);

        assertThatThrownBy(() -> suit.parseRole(invalidToken1))
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> suit.parseRole(invalidToken2))
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> suit.parseRole(invalidToken3))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("6. 정상적인 토큰을 파싱한다.(Happy Case)")
    void testLegalTokenParse() {
        // given
        String userName = "user";
        String userRole = "USER";
        String userToken = suit.issue(userName, userRole);

        // when
        String name = suit.parseName(userToken);
        String role = suit.parseRole(userToken);

        // then
        assertThat(name).isEqualTo(userName);
        assertThat(role).isEqualTo(userRole);
    }
}