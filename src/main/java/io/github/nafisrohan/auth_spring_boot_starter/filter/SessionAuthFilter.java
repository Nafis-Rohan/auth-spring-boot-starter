package io.github.nafisrohan.auth_spring_boot_starter.filter;

import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.SessionAuthStrategy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class SessionAuthFilter extends OncePerRequestFilter {

    private final SessionAuthStrategy sessionAuthStrategy;

    public SessionAuthFilter(SessionAuthStrategy sessionAuthStrategy) {
        this.sessionAuthStrategy = sessionAuthStrategy;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (sessionAuthStrategy.isAuthenticated(request)) {
            String username = (String) request.getSession(false).getAttribute("username");
            var auth = new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        chain.doFilter(request, response); //"I'm finished. Let the request continue to the next filter.
    }
}