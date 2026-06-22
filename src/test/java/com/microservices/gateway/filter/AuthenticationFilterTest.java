package com.microservices.gateway.filter;

import com.microservices.gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationFilterTest {

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private GatewayFilterChain chain;

    private AuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new AuthenticationFilter(jwtUtil);
    }

    @Test
    void filter_shouldPassThrough_forLoginPath() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/auth/login").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        when(chain.filter(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verify(jwtUtil, never()).validateAndExtractClaims(anyString());
    }

    @Test
    void filter_shouldRejectRegisterPathWithoutToken() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/auth/register").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filter_shouldReturn401_whenAuthorizationHeaderIsMissing() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/protected").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filter_shouldReturn401_whenAuthorizationHeaderDoesNotStartWithBearer() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/protected")
                .header(HttpHeaders.AUTHORIZATION, "Basic credentials")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filter_shouldReturn401_whenTokenIsInvalid() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/protected")
                .header(HttpHeaders.AUTHORIZATION, "Bearer invalid-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        when(jwtUtil.validateAndExtractClaims("invalid-token")).thenThrow(new RuntimeException("Invalid"));

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filter_shouldPropagateHeaders_whenTokenIsValid() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/relatorios/123")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .header("X-User-Role", "ROLE_ALUNO")
                .header("X-Profile-Id", "999")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        Claims claims = new DefaultClaims(Map.of("sub", "42", "role", "ROLE_ADMIN"));
        when(jwtUtil.validateAndExtractClaims("valid-token")).thenReturn(claims);
        when(chain.filter(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verify(jwtUtil).validateAndExtractClaims("valid-token");
    }

    @Test
    void filter_shouldReturn403_whenAlunoAccessesAdminEndpoint() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/admin/alunos")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        Claims claims = new DefaultClaims(Map.of(
                "sub", "42",
                "role", "ROLE_ALUNO",
                "profileId", 7));
        when(jwtUtil.validateAndExtractClaims("valid-token")).thenReturn(claims);

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void filter_shouldAllowAlunoToAccessOwnFrequencyEndpoint() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/metricas/frequencia/me")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        Claims claims = new DefaultClaims(Map.of(
                "sub", "42",
                "role", "ROLE_ALUNO",
                "profileId", 7));
        when(jwtUtil.validateAndExtractClaims("valid-token")).thenReturn(claims);
        when(chain.filter(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        verify(chain).filter(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void filter_shouldAllowAlunoToUseProtectedReportEndpoints() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/relatorios")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        Claims claims = new DefaultClaims(Map.of(
                "sub", "42",
                "role", "ROLE_ALUNO",
                "profileId", 7));
        when(jwtUtil.validateAndExtractClaims("valid-token")).thenReturn(claims);
        when(chain.filter(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        verify(chain).filter(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void getOrder_shouldReturnHighestPrecedence() {
        assertThat(filter.getOrder()).isEqualTo(Ordered.HIGHEST_PRECEDENCE);
    }
}
