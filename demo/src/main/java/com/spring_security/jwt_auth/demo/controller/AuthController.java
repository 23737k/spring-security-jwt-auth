package com.spring_security.jwt_auth.demo.controller;

import com.spring_security.jwt_auth.demo.security.authentication.AuthenticationService;
import com.spring_security.jwt_auth.demo.security.dto.request.AuthReq;
import com.spring_security.jwt_auth.demo.security.dto.request.ChangePasswordReq;
import com.spring_security.jwt_auth.demo.security.dto.request.RegisterReq;
import com.spring_security.jwt_auth.demo.security.dto.response.AuthRes;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.security.Principal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@ApiResponses({
    @ApiResponse(
        description = "Success",
        responseCode = "200",
        content = @Content(mediaType = "application/json", schema = @Schema(implementation = AuthRes.class))
    ),
    @ApiResponse(
        description = "Unauthorized / Invalid Token",
        responseCode = "401",
        content = @Content(mediaType = "text/plain")
    )
})
public class AuthController {
  private final AuthenticationService authenticationService;

  @Operation(summary = "User login", description = "Authenticates a user and returns an access token and a refresh token.\n\nThe access token should be included in the Authorization header for subsequent requests to access protected resources.\n\nThe refresh token is used to request a new access token when this expires.")
  @PostMapping("/login")
  public AuthRes login(@RequestBody @Valid AuthReq authReq) {
    return authenticationService.authenticate(authReq);
  }

  @Operation(summary = "User register", description = "Register a user and returns an access token and a refresh token.\n\nThe access token should be included in the Authorization header for subsequent requests to access protected resources.\n\nThe refresh token is used to request a new access token when this expires.")
  @PostMapping("/register")
  public AuthRes register(@RequestBody @Valid RegisterReq registerReq) {
    return authenticationService.register(registerReq);
  }

  @SecurityRequirement(name = "bearerAuth")
  @Operation(summary = "Renew access token", description = "Returns a new access and refresh token if a valid refresh token is provided in the Authorization header.\n\nConsider that refresh tokens can be used once. After that you must use the new one, provided in this endpoint.")
  @PostMapping("/renew-token")
  public AuthRes renewToken(HttpServletRequest request) {
    return authenticationService.renewToken(request);
  }


  @Operation(summary = "User Logout", description = "Logs out the user by invalidating the token. This endpoint is protected and requires a valid access token in the Authorization header.")
  @ApiResponses({
      @ApiResponse(
          description = "Logout Successful",
          responseCode = "200",
          content = @Content()
      ),
      @ApiResponse(
          description = "Unauthorized - Invalid Token",
          responseCode = "401",
          content = @Content()
      )
  })
  @SecurityRequirement(name = "bearerAuth")
  @PostMapping("/logout")
  public void logout() {
    // Este método no se ejecutará ya que Spring Security maneja el logout
  }

  @PostMapping("/change-password")
  public String changePassword(@RequestBody @Valid ChangePasswordReq changePasswordReq, Principal principal){
    return authenticationService.changePassword(principal, changePasswordReq);
  }

}
