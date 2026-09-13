package io.github.nafisrohan.auth_spring_boot_starter.controller;

import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.SessionAuthStrategy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final SessionAuthStrategy sessionAuthStrategy;

    public AuthController(SessionAuthStrategy sessionAuthStrategy) {
        this.sessionAuthStrategy = sessionAuthStrategy;
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password,
                        HttpServletRequest request, HttpServletResponse response) {
        sessionAuthStrategy.login(request, response, username, password);
        return "Logged in as " + username;
    }

    @GetMapping("/check")
    public String check(HttpServletRequest request) {
        boolean authenticated = sessionAuthStrategy.isAuthenticated(request);
        return authenticated ? "You are authenticated" : "You are NOT authenticated";
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        sessionAuthStrategy.logout(request, response);
        return "Logged out";
    }
}