package com.example.oauthdemo.controllers;

import com.example.oauthdemo.dto.JwtResponse;
import com.example.oauthdemo.services.GithubUserService;
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
    private final GithubUserService githubUserService;

    public LoginController(JwtService jwtService,
                           GithubUserService githubUserService) {
        this.jwtService = jwtService;
        this.githubUserService = githubUserService;
    }

    @GetMapping("/login")
    public JwtResponse login() {
        User principal = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String jwt = jwtService.generateToken(principal.getUsername());
        return new JwtResponse(jwt);
    }

    @GetMapping("/github/login")
    public JwtResponse githubLogin() {
        String jwt = jwtService.generateToken(githubUserService.getDefaultGithubUsername());
        return new JwtResponse(jwt);
    }

}
