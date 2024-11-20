package com.spring_security.jwt_auth.demo.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AccountNotVerifiedException extends RuntimeException {
  private String message;
}
