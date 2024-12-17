package com.springsecurity.jwt.api;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class ApiController {

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
}
