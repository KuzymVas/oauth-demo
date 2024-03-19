package com.example.oauthdemo.controllers;

import com.example.oauthdemo.dto.DemoResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for non-admin endpoints. Still only ADMIN role can do POST requests even to those endpoints
 */
@RestController()
@RequestMapping("/api")
public class DemoController {

    @GetMapping("/demo")
    public DemoResponse getDemo() {
        return new DemoResponse("Only those with USER role can access this");
    }


    @PostMapping("/demo")
    public DemoResponse postDemo() {
        return new DemoResponse("Only those with ADMIN role can do POST like this");
    }


}
