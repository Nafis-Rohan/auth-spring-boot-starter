package io.github.nafisrohan.auth_spring_boot_starter.core.strategies;

import io.github.nafisrohan.auth_spring_boot_starter.core.AuthStrategy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class SessionAuthStrategy implements AuthStrategy {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public SessionAuthStrategy(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    //getSession(true) -> Give me the HTTP session associated with this request.If there isn't a session, create one.
    @Override
    public void login(HttpServletRequest request, HttpServletResponse response, String username, String password) {
        // Look up the stored user and check the submitted password against
        // their real hashed password — this is the actual credential check
        // that was missing since Day 1.
        UserDetails storedUser = userDetailsService.loadUserByUsername(username);
        if (!passwordEncoder.matches(password, storedUser.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }

        HttpSession session = request.getSession(true);
        session.setAttribute("username", username);//Store the username inside this user's session
        request.changeSessionId(); // prevents session fixation — issues a fresh session ID after login
        //        Session ABC123
        //        username → "nafis"
    }

    //getSession(flase) -> Give me the HTTP session associated with this request.If there isn't a session, dont create one.
    @Override
    public boolean isAuthenticated(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session != null && session.getAttribute("username") != null;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate(); //Destroy this session.
        }
    }
}