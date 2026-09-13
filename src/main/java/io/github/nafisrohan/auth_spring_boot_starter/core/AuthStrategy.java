package io.github.nafisrohan.auth_spring_boot_starter.core;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthStrategy {

    /**
     * Called when a user logs in. Each strategy decides how to authenticate
     * (check password, verify token, etc.) and how to respond (set a cookie,
     * return a token, etc.)
     */
    void login(HttpServletRequest request, HttpServletResponse response, String username, String password);

    /**
     * Called on every incoming request to check if the user is authenticated.
     * Returns true if valid, false if not.
     */
    boolean isAuthenticated(HttpServletRequest request);

    /**
     * Called when a user logs out. Each strategy decides how to invalidate
     * (destroy session, blocklist token, etc.)
     */
    void logout(HttpServletRequest request, HttpServletResponse response);
}