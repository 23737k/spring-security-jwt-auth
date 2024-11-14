package com.spring_security.jwt_auth.demo.security.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RegisterReq {

  @Schema(example = "user@example.com")

  @NotNull(message = "The email must not be empty")
  @Email(message = "Invalid email format")
  private String email;

  @Schema(example = "P@ssw0rd!")

  @NotBlank(message = "The password must not be empty")
  @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
          , message = "The password must have: At least 8 characters. At least one uppercase letter. At least a lowercase letter. At least one number.At least one special character (eg. !, @, #, $, %, etc.) ")
  private String password;
}
