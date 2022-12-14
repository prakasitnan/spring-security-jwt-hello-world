package com.example.springsecurityjwthelloworld.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManager;

@WebMvcTest
public class AuthControllerTest {

    @MockBean
    AuthenticationManager authenticationManager;

    @BeforeEach
    void setUp() {

    }

    @Test
    void login() {

    }
}
