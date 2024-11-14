package com.spring_security.jwt_auth.demo.security.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthReq {

  @Schema(example = "user@example.com")
  @NotBlank(message = "The email must not be empty")
  private String email;

  @Schema(example = "P@ssw0rd!")
  @NotBlank(message = "The password must not be empty")
  private String password;
}
