package com.telemedicine.app.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "REFRESH_TOKENS",uniqueConstraints = @UniqueConstraint(
        name = "uk_refresh_token_hash",
        columnNames = "TOKEN_HASH"
))
@Getter
@Setter
public class RefreshToken {

    @Id
    @GeneratedValue
    @Column(name = "ID")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    private User user;

    @Column(name = "TOKEN_HASH", nullable = false)
    private String tokenHash;

    @Column(name = "FAMILY_ID")
    private UUID familyId;

    @Column(name = "EXPIRES_AT")
    private Instant expiresAt;

    @Column(name = "REVOKED_AT")
    private Instant revokedAt;

    @Column(name = "CREATED_IP")
    private String createdIp;

    @Column(name = "USER_AGENT")
    private String userAgent;
}
