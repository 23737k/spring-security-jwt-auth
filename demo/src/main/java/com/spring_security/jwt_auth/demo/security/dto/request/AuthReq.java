package com.spring_security.jwt_auth.demo.security.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthReq {
  @NotBlank(message = "El email no debe estar vacio")
  private String email;
  @NotBlank(message = "La contraseña no debe estar vacía")
  private String password;
}
