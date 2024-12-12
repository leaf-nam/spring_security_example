package com.springsecurity.jwt.api;

import com.springsecurity.jwt.Role;
import com.springsecurity.jwt.utility.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class ApiController {

    private final JwtUtil jwtUtil;

    @GetMapping("/admin/resources")
    public String getAdminResources() {
        return "ADMIN 자원 획득";
    }

    @GetMapping("/user/resources")
    public String getUserResources() {
        return "USER 자원 획득";
    }

    @GetMapping("/public/resources")
    public String getPublicResources() {
        return "PUBLIC 자원 획득";
    }

    @PostMapping("/jwt/token")
    public ResponseEntity<String> getToken(@RequestParam String username, @RequestParam String password) {

        if (username.equals("user") && password.equals("user1234"))
            return new ResponseEntity<>(jwtUtil.issue("user", Role.USER.name()), HttpStatus.OK);

        else if (username.equals("admin") && password.equals("admin1234"))
            return new ResponseEntity<>(jwtUtil.issue("admin", Role.ADMIN.name()), HttpStatus.OK);

        else return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }
}
