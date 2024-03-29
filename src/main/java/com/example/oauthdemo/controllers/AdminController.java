package com.example.oauthdemo.controllers;

import com.example.oauthdemo.dto.DemoResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for endpoints accessible only to ADMIN role
 */
@RestController()
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/demo")
    public DemoResponse getDemo() {
        return new DemoResponse("Only those with ADMIN role can access this");
    }


    @PostMapping("/demo")
    public DemoResponse postDemo() {
        return new DemoResponse("Only those with ADMIN role can do POST like this");
    }
}
