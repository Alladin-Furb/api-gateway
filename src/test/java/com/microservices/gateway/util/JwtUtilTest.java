package com.microservices.gateway.util;

import com.microservices.gateway.config.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtUtilTest {

    private static final String SECRET = "my-super-secret-key-that-is-at-least-32-chars-long!";

    private JwtUtil jwtUtil;
    private SecretKey signingKey;

    @BeforeEach
    void setUp() {
        JwtConfig config = new JwtConfig(SECRET);
        jwtUtil = new JwtUtil(config);
        signingKey = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateAndExtractClaims_shouldReturnClaims_forValidToken() {
        String token = buildToken("123", "ROLE_ALUNO", 3600000L);

        Claims claims = jwtUtil.validateAndExtractClaims(token);

        assertThat(claims.getSubject()).isEqualTo("123");
        assertThat(claims.get("role", String.class)).isEqualTo("ROLE_ALUNO");
    }

    @Test
    void validateAndExtractClaims_shouldThrow_forExpiredToken() {
        String token = buildToken("123", "ROLE_ALUNO", -1000L);

        assertThatThrownBy(() -> jwtUtil.validateAndExtractClaims(token))
                .isInstanceOf(Exception.class);
    }

    @Test
    void validateAndExtractClaims_shouldThrow_forTokenSignedWithDifferentKey() {
        SecretKey wrongKey = Keys.hmacShaKeyFor(
                "a-completely-different-secret-key-that-is-long-enough".getBytes(StandardCharsets.UTF_8));
        Date now = new Date();
        String token = Jwts.builder()
                .subject("123")
                .claim("role", "ROLE_ALUNO")
                .issuedAt(now)
                .expiration(new Date(now.getTime() + 3600000L))
                .signWith(wrongKey)
                .compact();

        assertThatThrownBy(() -> jwtUtil.validateAndExtractClaims(token))
                .isInstanceOf(SignatureException.class);
    }

    @Test
    void validateAndExtractClaims_shouldThrow_forMalformedToken() {
        assertThatThrownBy(() -> jwtUtil.validateAndExtractClaims("not.a.valid.token"))
                .isInstanceOf(Exception.class);
    }

    private String buildToken(String subject, String role, long expirationOffset) {
        Date now = new Date();
        return Jwts.builder()
                .subject(subject)
                .claim("role", role)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + expirationOffset))
                .signWith(signingKey)
                .compact();
    }
}
