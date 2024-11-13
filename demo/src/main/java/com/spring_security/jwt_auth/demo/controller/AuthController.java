package com.spring_security.jwt_auth.demo.controller;

import com.spring_security.jwt_auth.demo.security.authentication.AuthenticationService;
import com.spring_security.jwt_auth.demo.security.dto.request.AuthReq;
import com.spring_security.jwt_auth.demo.security.dto.request.RegisterReq;
import com.spring_security.jwt_auth.demo.security.dto.response.AuthRes;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
  private final AuthenticationService authenticationService;

  @PostMapping("/login")
  public AuthRes login(@RequestBody @Valid AuthReq authReq) {
    return authenticationService.authenticate(authReq);
  }

  @PostMapping("/register")
  public AuthRes register(@RequestBody @Valid RegisterReq registerReq) {
    return authenticationService.register(registerReq);
  }

  @PostMapping("/renew-token")
  public AuthRes renewToken(HttpServletRequest request) {
    return authenticationService.renewToken(request);
  }

}
