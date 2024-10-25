package com.example.jwt_demo.dto;

import com.example.jwt_demo.entity.UserRole;

// dtos/SignUpDto.java
public record SignUpDto(
        String login,
        String password,
        UserRole role) {
}
