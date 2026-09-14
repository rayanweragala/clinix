package com.telemedicine.app.configuration;

import com.telemedicine.app.common.SameSite;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

@Validated
@ConfigurationProperties("telemedicine.security")
public record SecurityProperties(

        @NotBlank String issuer,
        @NotBlank String audience,
        @NotBlank String jwtSecretBase64,
        @NotNull Duration accessTokenTtl,
        @NotNull Duration refreshTokenTtl,
        @NotEmpty List<String> allowedOrigins,
        @NotNull @Valid CookieSettings cookies
) {

    public record CookieSettings(
            boolean secure,
            @NotNull SameSite sameSite
    ){
    }
}
