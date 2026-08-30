package com.telemedicine.app.security;

import com.telemedicine.app.configuration.SecurityProperties;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@Service
public class TokenCookeService {

    private final SecurityProperties securityProperties;

    public void writeAccessToken(HttpServletResponse response, String accessToken) {
        ResponseCookie cookie = ResponseCookie.from(SecurityCookies.ACCESS_TOKEN, accessToken)
                .httpOnly(true)
                .secure(securityProperties.cookies().secure())
                .sameSite(securityProperties.cookies().sameSite().name())
                .path("/")
                .maxAge(securityProperties.accessTokenTtl())
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public void writeRefreshToken(HttpServletResponse response, String refreshToken){
        ResponseCookie cookie = ResponseCookie.from(SecurityCookies.REFRESH_TOKEN, refreshToken)
                .httpOnly(true)
                .secure(securityProperties.cookies().secure())
                .sameSite(securityProperties.cookies().sameSite().name())
                .path("/api/v1/auth")
                .maxAge(securityProperties.refreshTokenTtl())
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public void clearAuthenticationCookies(HttpServletResponse response){
        response.addHeader(HttpHeaders.SET_COOKIE, expiredCookie(SecurityCookies.ACCESS_TOKEN,"/").toString());
        response.addHeader(HttpHeaders.SET_COOKIE, expiredCookie(SecurityCookies.REFRESH_TOKEN,"/api/v1/auth").toString());
    }

    private ResponseCookie expiredCookie(String name, String path) {
        return ResponseCookie.from(name, "")
                .httpOnly(true)
                .secure(securityProperties.cookies().secure())
                .sameSite(securityProperties.cookies().sameSite().name())
                .path(path)
                .maxAge(0)
                .build();
    }
}
