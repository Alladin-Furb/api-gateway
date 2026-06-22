package com.microservices.gateway.filter;

import com.microservices.gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.UUID;

@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationFilter.class);

    private static final String CORRELATION_ID_HEADER = "X-Correlation-Id";
    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String USER_ROLE_HEADER = "X-User-Role";
    private static final String PROFILE_ID_HEADER = "X-Profile-Id";
    private static final String BEARER_PREFIX = "Bearer ";

    private static final Set<String> PUBLIC_PATHS = Set.of(
            "/api/auth/login",
            "/api/auth/register"
    );

    private final JwtUtil jwtUtil;

    public AuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String correlationId = exchange.getRequest().getHeaders()
                .getFirst(CORRELATION_ID_HEADER);
        if (correlationId == null || correlationId.isBlank()) {
            correlationId = UUID.randomUUID().toString();
        }
        String path = exchange.getRequest().getURI().getPath();

        log.info("correlationId={} | method={} path={}", correlationId,
                exchange.getRequest().getMethod(), path);

        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove(USER_ID_HEADER);
                    headers.remove(USER_ROLE_HEADER);
                    headers.remove(PROFILE_ID_HEADER);
                    headers.remove(CORRELATION_ID_HEADER);
                })
                .header(CORRELATION_ID_HEADER, correlationId);
        exchange.getResponse().getHeaders().set(CORRELATION_ID_HEADER, correlationId);

        if (PUBLIC_PATHS.contains(path)) {
            return chain.filter(
                    exchange.mutate().request(requestBuilder.build()).build());
        }

        String authHeader = exchange.getRequest().getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return unauthorizedResponse(exchange.getResponse(), correlationId);
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        try {
            Claims claims = jwtUtil.validateAndExtractClaims(token);
            String role = claims.get("role", String.class);
            String profileId = claims.get("profileId") == null
                    ? null
                    : String.valueOf(claims.get("profileId"));

            if (!isAuthorized(
                    exchange.getRequest().getMethod().name(),
                    path,
                    role)) {
                return forbiddenResponse(exchange.getResponse(), correlationId);
            }

            requestBuilder
                    .header(USER_ID_HEADER, claims.getSubject())
                    .header(USER_ROLE_HEADER, role);
            if (profileId != null) {
                requestBuilder.header(PROFILE_ID_HEADER, profileId);
            }

            return chain.filter(
                    exchange.mutate().request(requestBuilder.build()).build());
        } catch (Exception e) {
            log.warn("correlationId={} | JWT validation failed: {}", correlationId, e.getMessage());
            return unauthorizedResponse(exchange.getResponse(), correlationId);
        }
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    private Mono<Void> unauthorizedResponse(ServerHttpResponse response, String correlationId) {
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().set(CORRELATION_ID_HEADER, correlationId);

        String body = """
                {"error":"Unauthorized","message":"Invalid or missing authentication token"}""";
        DataBuffer buffer = response.bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    private Mono<Void> forbiddenResponse(ServerHttpResponse response, String correlationId) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().set(CORRELATION_ID_HEADER, correlationId);

        String body = """
                {"error":"Forbidden","message":"Insufficient permissions"}""";
        DataBuffer buffer = response.bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    private boolean isAuthorized(String method, String path, String role) {
        if ("ROLE_ADMIN".equals(role)) {
            return true;
        }

        if ("ROLE_MOTORISTA".equals(role)) {
            return path.equals("/api/relatorios")
                    || path.startsWith("/api/relatorios/")
                    || path.startsWith("/api/metricas/")
                    || path.startsWith("/api/indicadores/")
                    || path.startsWith("/api/rotas/");
        }

        if (!"ROLE_ALUNO".equals(role)) {
            return false;
        }

        if (path.equals("/api/metricas/frequencia/me")) {
            return "GET".equals(method);
        }

        if (path.equals("/api/relatorios")
                || path.startsWith("/api/relatorios/")) {
            return Set.of("GET", "POST").contains(method);
        }

        if (path.startsWith("/api/v1/presencas/aluno/")) {
            return Set.of("GET", "POST").contains(method);
        }

        return "GET".equals(method)
                && (path.equals("/api/v1/cursos")
                    || path.startsWith("/api/v1/cursos/"));
    }
}
