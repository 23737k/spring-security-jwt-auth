package com.spring_security.jwt_auth.demo.config;


import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

@OpenAPIDefinition(
    info = @Info(
        title = "Jwt authentication API",
        description = "A JWT authentication implementation with Spring Security"
    )
)
@SecurityScheme(
    type = SecuritySchemeType.HTTP,
    scheme = "bearer",
    name = "bearerAuth",
    in = SecuritySchemeIn.HEADER,
    bearerFormat = "JWT"
)
public class SwaggerConfig {
}
