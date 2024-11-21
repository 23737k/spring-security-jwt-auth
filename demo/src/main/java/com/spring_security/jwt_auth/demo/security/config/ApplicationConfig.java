package com.spring_security.jwt_auth.demo.security.config;

import com.spring_security.jwt_auth.demo.repository.UserRepository;
import com.spring_security.jwt_auth.demo.security.jwt.JwtService;
import com.spring_security.jwt_auth.demo.security.token.ActiveTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
  private final UserRepository userRepository;

  @Bean
  AuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
    daoAuthenticationProvider.setUserDetailsService(userDetailsService());
    daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
    return daoAuthenticationProvider;
  }

  @Bean
  public UserDetailsService userDetailsService() {
    return username -> userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException(username));
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }


  @Bean
  public LogoutHandler logoutHandler(ActiveTokenRepository tokenRepository, JwtService jwtService) {
    return (request, response, authentication) -> {
      final String header = request.getHeader("Authorization");
      if (header != null && header.startsWith("Bearer ")) {
        final String token = header.substring(7);
        tokenRepository.deleteByUserEmail(jwtService.extractUsername(token));
        }
      };
  }
}
