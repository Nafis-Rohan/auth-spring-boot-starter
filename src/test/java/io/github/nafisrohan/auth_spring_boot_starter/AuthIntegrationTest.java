package io.github.nafisrohan.auth_spring_boot_starter;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "unifyauth.test-user.enabled=true",
        "unifyauth.form-login.enabled=true"
})
class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void jwtLogin_withCorrectCredentials_succeeds() throws Exception {
        mockMvc.perform(post("/auth/jwt/login")
                        .param("username", "nafis")
                        .param("password", "password")
                        .with(csrf()))
                .andExpect(status().isOk());
    }

    @Test
    void jwtLogin_withWrongPassword_returns401() throws Exception {
        mockMvc.perform(post("/auth/jwt/login")
                        .param("username", "nafis")
                        .param("password", "wrongpassword")
                        .with(csrf()))
                .andExpect(status().isUnauthorized());
    }
}