package com.spring_security.jwt_auth.demo.security.authentication;

import com.spring_security.jwt_auth.demo.exception.InvalidRefreshTokenException;
import com.spring_security.jwt_auth.demo.model.User;
import com.spring_security.jwt_auth.demo.security.dto.request.AuthReq;
import com.spring_security.jwt_auth.demo.security.dto.request.ChangePasswordReq;
import com.spring_security.jwt_auth.demo.security.dto.request.RegisterReq;
import com.spring_security.jwt_auth.demo.security.dto.response.AuthRes;
import com.spring_security.jwt_auth.demo.security.jwt.JwtService;
import com.spring_security.jwt_auth.demo.security.token.RefreshToken;
import com.spring_security.jwt_auth.demo.security.token.RefreshTokenRepository;
import com.spring_security.jwt_auth.demo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final JwtService jwtService;
  private final AuthenticationProvider authenticationProvider;
  private final UserService userService;
  private final RefreshTokenRepository tokenRepository;

  @Transactional
  public AuthRes authenticate(AuthReq authReq) {

    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(authReq.getEmail(), authReq.getPassword());
    Authentication auth = authenticationProvider.authenticate(authentication);
    User user = (User) auth.getPrincipal();

    tokenRepository.deleteByUser(user);
    return getAuthRes(user);
  }

  public AuthRes register(RegisterReq registerReq) {
    User user = userService.createUser(registerReq);
    return getAuthRes(user);
  }


  @Transactional
  public AuthRes renewToken(HttpServletRequest request) {
    String header = request.getHeader("Authorization");

    if(header != null && header.startsWith("Bearer ")){
      String refreshToken = header.substring(7);
      String userEmail = jwtService.extractUsername(refreshToken);
      boolean isExpired = jwtService.isTokenExpired(refreshToken);
      boolean isValid = tokenRepository.existsByToken(refreshToken);
      if(userEmail != null && !isExpired && isValid){
        User user = userService.findUserByEmail(userEmail);
        tokenRepository.deleteByUser(user);
        return getAuthRes(user);
      }
      else
        throw new InvalidRefreshTokenException("The refresh token is not valid or it has already been used");
    }
    else
      throw new InvalidRefreshTokenException("The refresh token is not valid or it has already been used");
  }

  @Transactional
  public String changePassword(Principal principal, ChangePasswordReq changePasswordReq) {
    User user = (User) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();
    userService.changePassword(user, changePasswordReq);
    return "Password changed";
  }


  private AuthRes getAuthRes(User user) {
    String accessToken = jwtService.generateAccessToken(user);
    String refreshToken = jwtService.generateRefreshToken(user);

    tokenRepository.save(RefreshToken.builder()
        .token(refreshToken)
        .user(user)
        .build());

    return new AuthRes(accessToken, refreshToken);
  }
}
