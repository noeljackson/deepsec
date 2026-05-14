package com.example.api;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    @CrossOrigin(origins = "*", allowCredentials = "true")
    @GetMapping("/profile")
    public String profileVulnerable() {
        return "{}";
    }

    @CrossOrigin(origins = "https://example.com")
    @GetMapping("/health")
    public String healthSafe() {
        return "ok";
    }
}
