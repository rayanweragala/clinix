package com.telemedicine.app.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Set;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;

public class CookieBearerTokenResolver implements BearerTokenResolver {

    private static final Set<String> ACCESS_TOKEN_IGNORED_PATHS =
            Set.of(
                    "/api/v1/auth/csrf",
                    "/api/v1/auth/register",
                    "/api/v1/auth/login",
                    "/api/v1/auth/refresh",
                    "/api/v1/auth/logout");

    @Override
    public String resolve(HttpServletRequest request) {
        String path = request.getServletPath();

        if (ACCESS_TOKEN_IGNORED_PATHS.contains(path)) {
            return null;
        }

        if (path.startsWith("/api/v1/public") || path.startsWith("/actuator/health")) {
            return null;
        }

        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            return null;
        }

        return Arrays.stream(cookies)
                .filter(cookie -> SecurityCookies.ACCESS_TOKEN.equals(cookie.getName()))
                .map(Cookie::getValue)
                .filter(value -> value != null && !value.isBlank())
                .findFirst()
                .orElse(null);
    }
}
