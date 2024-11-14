package com.spring_security.jwt_auth.demo.security.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RegisterReq {

  @Schema(example = "user@example.com")

  @NotNull(message = "El email no debe ser nulo")
  @Email(message = "Email con formato incorrecto")
  private String email;

  @Schema(example = "P@ssw0rd!")

  @NotNull(message = "La contraseña no debe ser nula")
  @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
      , message = "La contraseña debe tener: Longitud mínima de 8 caracteres. Al menos una letra mayúscula. Al menos una letra minúscula. Al menos un número. Al menos un carácter especial (como !, @, #, $, %, etc.) ")
  private String password;
}
