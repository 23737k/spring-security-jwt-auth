package com.spring_security.jwt_auth.demo.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
  private final String secretKey;
  @Value("${security.jwt.expiration}")
  private long expiration;

  public JwtService() {
    try {
      KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
      SecretKey sk = generator.generateKey();
      this.secretKey = Base64.getEncoder().encodeToString(sk.getEncoded());
    }
    catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }


  public String generateToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>();
    return Jwts.builder()
        .claims(claims)
        .subject(userDetails.getUsername())
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + expiration))
        .signWith(getSecretKey())
        .compact();
  }


  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public Date extractExpiration(String token) {
    return extractClaim(token,Claims::getExpiration);
  }

  public boolean isTokenExpired (String token) {
    return extractExpiration(token).before(new Date());
  }

  public boolean isTokenValid(String token, UserDetails userDetails) {
    return !isTokenExpired(token) && extractUsername(token).equals(userDetails.getUsername());
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
    return claimsResolver.apply(extractAllClaims(token));
  }

  public Claims extractAllClaims(String token){
    SecretKey  secretKey = (SecretKey) getSecretKey();
    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }



  public Key getSecretKey() {
    byte[] keyBytes = Base64.getDecoder().decode(secretKey);
    return Keys.hmacShaKeyFor(keyBytes);
  }

}
