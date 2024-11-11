package com.spring_security.jwt_auth.demo.security.jwt;

import com.spring_security.jwt_auth.demo.security.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  private final UserDetailsService userDetailsService;
  private final JwtService jwtService;
  private final TokenRepository tokenRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {

    final String header = request.getHeader("Authorization");

    if (header != null && header.startsWith("Bearer ")) {
      final String token = header.substring(7);
      final String username = jwtService.extractUsername(token);

      if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        boolean isTokenValid = tokenRepository.findByAccessToken(token)
                .map(t-> !t.isExpired() && !t.isRevoked() ).orElse(false);

        if(jwtService.isTokenValid(token, userDetails) && isTokenValid){
          UsernamePasswordAuthenticationToken
              authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
          authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

          SecurityContextHolder.getContext().setAuthentication(authentication);
        }
      }


    }

    filterChain.doFilter(request, response);

  }
}
