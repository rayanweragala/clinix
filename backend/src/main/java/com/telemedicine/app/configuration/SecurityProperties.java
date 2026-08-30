package com.telemedicine.app.configuration;

import com.telemedicine.app.common.SameSite;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

@Validated
@ConfigurationProperties("telemedicine.security")
public record SecurityProperties(

        String issuer,
        String audience,
        String jwtSecretBase64,
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        List<String> allowedOrigins,
        CookieSettings cookies
) {

    public record CookieSettings(
            boolean secure,
            SameSite sameSite
    ){
    }
}
