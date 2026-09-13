package io.github.nafisrohan.auth_spring_boot_starter.core.strategies;

import io.github.nafisrohan.auth_spring_boot_starter.core.AuthStrategy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Component;

@Component
public class SessionAuthStrategy implements AuthStrategy {

    //getSession(true) -> Give me the HTTP session associated with this request.If there isn't a session, create one.
    @Override
    public void login(HttpServletRequest request, HttpServletResponse response, String username, String password) {
        HttpSession session = request.getSession(true);
        session.setAttribute("username", username); //Store the username inside this user's session
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