package com.spring_security.jwt_auth.demo.service;

import com.spring_security.jwt_auth.demo.exception.DuplicateEmailException;
import com.spring_security.jwt_auth.demo.model.User;
import com.spring_security.jwt_auth.demo.repository.UserRepository;
import com.spring_security.jwt_auth.demo.security.dto.request.RegisterReq;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public User createUser(RegisterReq registerReq) {

    if(userRepository.existsByEmail(registerReq.getEmail()))
      throw new DuplicateEmailException("El email ya se encuentra registrado");

    User user = User.builder()
        .email(registerReq.getEmail())
        .password(passwordEncoder.encode(registerReq.getPassword()))
        .build();
    return userRepository.save(user);
  }
}
