package com.spring_security.jwt_auth.demo.security.authentication;

import com.spring_security.jwt_auth.demo.model.User;
import com.spring_security.jwt_auth.demo.security.dto.request.AuthReq;
import com.spring_security.jwt_auth.demo.security.dto.request.RegisterReq;
import com.spring_security.jwt_auth.demo.security.dto.response.AuthRes;
import com.spring_security.jwt_auth.demo.security.jwt.JwtService;
import com.spring_security.jwt_auth.demo.security.token.Token;
import com.spring_security.jwt_auth.demo.security.token.TokenRepository;
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
  private final TokenRepository tokenRepository;

  public AuthRes authenticate(AuthReq authReq) {
    UsernamePasswordAuthenticationToken authentication =
        new UsernamePasswordAuthenticationToken(authReq.getEmail(), authReq.getPassword());

    Authentication auth = authenticationProvider.authenticate(authentication);
    User user = (User) auth.getPrincipal();

    Token token = getToken(user);

    return new AuthRes(token.getAccessToken());
  }

  private Token getToken(User user) {
    tokenRepository.findByUser(user).forEach(t -> {
      t.setExpired(true);
      t.setRevoked(true);
      tokenRepository.save(t);
    });

      Token token =  Token.builder()
            .accessToken(jwtService.generateToken(user))
            .user(user)
            .build();
      return tokenRepository.save(token);
  }

  public AuthRes register(RegisterReq registerReq) {
    User user = userService.createUser(registerReq);
    Token token = getToken(user);
    return new AuthRes(token.getAccessToken());
  }
}
