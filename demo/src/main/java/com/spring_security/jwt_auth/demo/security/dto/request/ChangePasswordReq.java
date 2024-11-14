package com.spring_security.jwt_auth.demo.security.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@AllArgsConstructor
@Builder
@Data
public class ChangePasswordReq {
  @NotBlank(message = "oldPassword must not be empty")
  private String oldPassword;
  @NotBlank(message = "newPassword must not be empty")
  private String newPassword;
  @NotBlank(message = "confirmPassword must not be empty")
  private String confirmPassword;
}
