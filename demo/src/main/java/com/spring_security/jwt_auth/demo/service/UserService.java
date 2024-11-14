package com.spring_security.jwt_auth.demo.service;

import com.spring_security.jwt_auth.demo.exception.DuplicateEmailException;
import com.spring_security.jwt_auth.demo.exception.NewPasswordMismatchException;
import com.spring_security.jwt_auth.demo.exception.OldPasswordMismatchException;
import com.spring_security.jwt_auth.demo.model.User;
import com.spring_security.jwt_auth.demo.repository.UserRepository;
import com.spring_security.jwt_auth.demo.security.dto.request.ChangePasswordReq;
import com.spring_security.jwt_auth.demo.security.dto.request.RegisterReq;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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

  public User findUserByEmail(String email) {
    return userRepository.findByEmail(email).orElseThrow(()-> new UsernameNotFoundException("Usuario con email: " + email + " no existe"));
  }


  public void changePassword(User user, ChangePasswordReq changePasswordReq) {
    String oldPassword = changePasswordReq.getCurrentPassword();
    String newPassword = changePasswordReq.getNewPassword();
    String confirmPassword = changePasswordReq.getConfirmPassword();


    if(!newPassword.equals(confirmPassword)){
      throw new NewPasswordMismatchException("New password does not match confirm password");
    }

    newPassword = passwordEncoder.encode(newPassword);

    if(!passwordEncoder.matches(oldPassword, user.getPassword())){
      throw new OldPasswordMismatchException("Old password is incorrect");
    }

    // Actualizar la contraseña
    user.setPassword(newPassword);
    userRepository.save(user);
  }
}
