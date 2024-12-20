package com.spring_security.jwt_auth.demo.security.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@AllArgsConstructor
@Builder
@Data
public class ChangePasswordReq {
  @Schema(example = "P@ssw0rd!")
  @NotBlank(message = "currentPassword must not be empty")
  private String currentPassword;

  @Schema(example = "S3cretP@ss!")
  @NotBlank(message = "newPassword must not be empty")
  @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
          , message = "The password must have: At least 8 characters. At least one uppercase letter. At least a lowercase letter. At least one number.At least one special character (eg. !, @, #, $, %, etc.) ")
  private String newPassword;

  @Schema(example = "S3cretP@ss!")
  @NotBlank(message = "confirmPassword must not be empty")
  @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
          , message = "The password must have: At least 8 characters. At least one uppercase letter. At least a lowercase letter. At least one number.At least one special character (eg. !, @, #, $, %, etc.) ")
  private String confirmPassword;
}
