package io.github.nafisrohan.auth_spring_boot_starter.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
public class TestController {

    @GetMapping("/protected-test")
    public String protectedTest() {
        return "You reached a protected endpoint!";
    }

    @GetMapping("/admin-only")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminOnly() {
        return "Welcome, admin! You have access to this resource.";
    }

    @GetMapping("/my-resource/{username}")
    public String myResource(@PathVariable String username, Authentication authentication) {
        if (!authentication.getName().equals(username)) {
            return "403 - You can only access your own resource";
        }
        return "Here is " + username + "'s private resource";
    }
}



