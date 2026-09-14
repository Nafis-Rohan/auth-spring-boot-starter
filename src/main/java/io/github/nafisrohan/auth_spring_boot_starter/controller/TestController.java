package io.github.nafisrohan.auth_spring_boot_starter.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/protected-test")
    public String protectedTest() {
        return "You reached a protected endpoint!";
    }
}