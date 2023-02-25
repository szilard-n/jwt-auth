package com.example.jwtauth.controller;

import com.example.jwtauth.entity.User;
import com.example.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/hello")
@RequiredArgsConstructor
public class HelloController {

    final UserRepository userRepository;

    @GetMapping
    public ResponseEntity<String> createUser(@RequestBody User user) {
        return ResponseEntity.ok("Hello, World!");
    }

}
