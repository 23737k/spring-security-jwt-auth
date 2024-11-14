package com.spring_security.jwt_auth.demo.security.authentication;

import com.spring_security.jwt_auth.demo.exception.InvalidRefreshTokenException;
import com.spring_security.jwt_auth.demo.exception.NewPasswordMismatchException;
import com.spring_security.jwt_auth.demo.exception.OldPasswordMismatchException;
import com.spring_security.jwt_auth.demo.model.User;
import com.spring_security.jwt_auth.demo.security.dto.request.AuthReq;
import com.spring_security.jwt_auth.demo.security.dto.request.ChangePasswordReq;
import com.spring_security.jwt_auth.demo.security.dto.request.RegisterReq;
import com.spring_security.jwt_auth.demo.security.dto.response.AuthRes;
import com.spring_security.jwt_auth.demo.security.jwt.JwtService;
import com.spring_security.jwt_auth.demo.security.token.Token;
import com.spring_security.jwt_auth.demo.security.token.TokenRepository;
import com.spring_security.jwt_auth.demo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
    revokeAllUserTokens(user);
    Token token = getToken(user);
    return new AuthRes(token.getAccessToken(), token.getRefreshToken());
  }

  public AuthRes register(RegisterReq registerReq) {
    User user = userService.createUser(registerReq);
    revokeAllUserTokens(user);
    Token token = getToken(user);
    return new AuthRes(token.getAccessToken(),token.getRefreshToken());
  }

  private Token getToken(User user) {
        Token token =  Token.builder()
        .accessToken(jwtService.generateAccessToken(user))
        .refreshToken(jwtService.generateRefreshToken(user))
        .user(user)
        .build();
    return tokenRepository.save(token);
  }

  private void revokeAllUserTokens(User user) {
    tokenRepository.findByUser(user).forEach(t -> {
      t.setExpired(true);
      t.setRevoked(true);
      tokenRepository.save(t);
    });
  }

  public AuthRes renewToken(HttpServletRequest request) {
    String header = request.getHeader("Authorization");

    if(header != null && header.startsWith("Bearer ")){
      String refreshToken = header.substring(7);
      String userEmail = jwtService.extractUsername(refreshToken);
      boolean isRefreshTokenValid = tokenRepository.findByRefreshToken(refreshToken)
              .map(t-> !t.isExpired() && !t.isRevoked() ).orElse(false);

      if(userEmail != null && isRefreshTokenValid ){
        User user = userService.findUserByEmail(userEmail);
        revokeAllUserTokens(user);
        Token token = getToken(user);

        return new AuthRes(token.getAccessToken(),token.getRefreshToken());
      }
      else
        throw new InvalidRefreshTokenException("El refresh token no es valido o ya ha sido utilizado");
    }
    else
      throw new InvalidRefreshTokenException("El refresh token no es valido o ya ha sido utilizado");
  }

  public String changePassword(Principal principal, ChangePasswordReq changePasswordReq) {
    User user = (User) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();
    userService.changePassword(user, changePasswordReq);
    return "Password changed";
  }
}
