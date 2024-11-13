package com.spring_security.jwt_auth.demo.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class InvalidRefreshTokenException extends RuntimeException{
    private String message;
}
