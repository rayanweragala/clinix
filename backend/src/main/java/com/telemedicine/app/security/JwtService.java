package com.telemedicine.app.security;

import com.telemedicine.app.configuration.SecurityProperties;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@AllArgsConstructor
@Service
public class JwtService {

    private final JwtEncoder jwtEncder;
    private final SecurityProperties properties;
    private final Clock clock;

    public IssuedToken issue(UUID userId, String role) {
        Instant issuedAt = clock.instant();
        Instant expiresAt = issuedAt.plus(properties.accessTokenTtl());

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer(properties.issuer())
                .audience(List.of(properties.audience()))
                .subject(userId.toString())
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .claim("role", role)
                .claim("token_type", "access")
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).type("JWT").build();

        String token = jwtEncder.encode(JwtEncoderParameters.from(header, claimsSet))
                .getTokenValue();

        return new IssuedToken(token, expiresAt);
    }

    public record IssuedToken(
            String value,
            Instant expiresAt
    ) {
    }
}
