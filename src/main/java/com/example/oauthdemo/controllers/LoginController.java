package com.example.oauthdemo.controllers;

import com.example.oauthdemo.dto.JwtResponse;
import com.example.oauthdemo.services.JwtService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController()
@RequestMapping("/api")
public class LoginController {

    private final JwtService jwtService;

    public LoginController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @GetMapping("/login")
    public JwtResponse getDemo() {
        User principal = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String jwt = jwtService.generateToken(principal.getUsername());
        return new JwtResponse(jwt);
    }

}
