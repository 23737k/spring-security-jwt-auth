package com.spring_security.jwt_auth.demo.security.authentication;

import com.spring_security.jwt_auth.demo.model.User;
import com.spring_security.jwt_auth.demo.security.dto.request.AuthReq;
import com.spring_security.jwt_auth.demo.security.dto.request.RegisterReq;
import com.spring_security.jwt_auth.demo.security.dto.response.AuthRes;
import com.spring_security.jwt_auth.demo.security.jwt.JwtService;
import com.spring_security.jwt_auth.demo.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final JwtService jwtService;
  private final AuthenticationProvider authenticationProvider;
  private final UserService userService;

  public AuthRes authenticate(AuthReq authReq) {
    UsernamePasswordAuthenticationToken authentication =
        new UsernamePasswordAuthenticationToken(authReq.getEmail(), authReq.getPassword());

    Authentication auth = authenticationProvider.authenticate(authentication);
    User user = (User) auth.getPrincipal();

    String token = jwtService.generateToken(user);
    return new AuthRes(token);
  }

  public AuthRes register(RegisterReq registerReq) {
    User user = userService.createUser(registerReq);
    String token = jwtService.generateToken(user);
    return new AuthRes(token);
  }
}
