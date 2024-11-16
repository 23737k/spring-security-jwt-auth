package com.spring_security.jwt_auth.demo.security.jwt;

import static com.spring_security.jwt_auth.demo.security.token.TokenPurpose.ACCESS_TOKEN;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
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

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                  FilterChain filterChain) throws IOException {

    try {
      final String header = request.getHeader("Authorization");

      if (header != null && header.startsWith("Bearer ")) {
        final String token = header.substring(7);
        final String username = jwtService.extractUsername(token);

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
          UserDetails userDetails = userDetailsService.loadUserByUsername(username);

          boolean isAccessToken = jwtService.extractClaim(token, c -> c.get("purpose")).equals(ACCESS_TOKEN.name());

          if(jwtService.isTokenValid(token, userDetails) && isAccessToken){
            UsernamePasswordAuthenticationToken
                authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
          }
        }

      }
      filterChain.doFilter(request, response);
    } catch (Exception e) {
      sendErrorResponse(response,e.getMessage());
    }

  }

  public void sendErrorResponse(HttpServletResponse response, String message) throws IOException {
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.getWriter().write(message);
    response.setContentType("application/json");
  }

}
