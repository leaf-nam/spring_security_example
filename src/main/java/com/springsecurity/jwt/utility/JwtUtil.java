package com.springsecurity.jwt.utility;

import com.springsecurity.jwt.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class JwtUtil {
    public void validate(String token) {
        Jwts.parser()
                .verifyWith(secretKey())
                .build()
                .parseSignedClaims(token);
    }

    private SecretKey secretKey() {
        // https://randomkeygen.com/
        return Keys.hmacShaKeyFor("+*jhLeu04kw7M~tQew<Ym<d%,\"{(PC$p64acJ}lH_;d:'nD/^s+y7O=j!FBia5b".getBytes(StandardCharsets.UTF_8));
    }

    public String issue(String userName, String role) {
        if (!Role.isValid(role)) throw new EnumConstantNotPresentException(Role.class, role);
        return Jwts.builder()
                .subject(userName)
                .claim("role", role)
                .signWith(secretKey())
                .compact();
    }

    public String parseName(String token) {
        return getPayload(token).getSubject();
    }

    public String parseRole(String token) {
        return (String) getPayload(token).get("role");
    }

    private Claims getPayload(String token) {
        return Jwts.parser()
                .verifyWith(secretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}
