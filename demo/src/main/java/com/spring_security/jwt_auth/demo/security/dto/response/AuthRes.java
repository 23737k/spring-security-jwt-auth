package com.spring_security.jwt_auth.demo.security.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthRes {
  private String accessToken;
  private String refreshToken;
}
