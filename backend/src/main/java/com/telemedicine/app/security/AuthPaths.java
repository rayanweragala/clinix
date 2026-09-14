package com.telemedicine.app.security;

import java.util.Set;

public final class AuthPaths {

    public static final Set<String> PUBLIC = Set.of(
            "/api/v1/auth/csrf",
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/api/v1/auth/logout",
            "/api/v1/auth/forgot-password",
            "/api/v1/auth/reset-password");

    private AuthPaths() {
    }
}
