/*
 * Copyright 2026 SK Broadband Co., Ltd. (Cloud X Dev. Team). All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.skbroadband.zerotrust.pep;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

/**
 * The enforcement decision for one request, shared by both filter shapes.
 *
 * <p>The global filter and the per-route filter differ only in how Spring registers them.
 * The rules they apply must not differ — that divergence is exactly what this library exists
 * to end, so the logic lives here once.
 */
class PepEnforcement {

    private final DecisionClient decisions;
    private final JwtVerifier jwt;

    PepEnforcement(DecisionClient decisions, JwtVerifier jwt) {
        this.decisions = decisions;
        this.jwt = jwt;
    }

    Mono<Void> enforce(ServerWebExchange exchange, GatewayFilterChain chain) {
        String token = bearer(exchange);
        if (token == null) {
            return deny(exchange, HttpStatus.UNAUTHORIZED, ReasonCodes.CREDENTIAL_REJECTED);
        }

        JwtVerifier.Claims claims;
        try {
            claims = jwt.verify(token, Instant.now().getEpochSecond());
        } catch (JwtVerifier.JwtException e) {
            return deny(exchange, HttpStatus.UNAUTHORIZED, ReasonCodes.CREDENTIAL_REJECTED);
        }

        String path = exchange.getRequest().getPath().value();
        String method = exchange.getRequest().getMethod().name();
        List<String> roles = claims.roles;

        return decisions.authorize(claims.sub, roles, path, method)
                .flatMap(decision -> {
                    if (!decision.allow()) {
                        return deny(exchange, HttpStatus.FORBIDDEN, decision.reasonCode());
                    }
                    ServerWebExchange mutated = exchange.mutate()
                            .request(exchange.getRequest().mutate()
                                    .header("X-ZT-Subject", claims.sub)
                                    .build())
                            .build();
                    return chain.filter(mutated);
                });
    }

    private static String bearer(ServerWebExchange exchange) {
        String header = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String value = header.substring(7).trim();
            return value.isEmpty() ? null : value;
        }
        return null;
    }

    /**
     * Writes the denial.
     *
     * <p>The reason code goes in the body rather than a header so that it survives proxies
     * that strip unknown headers, and so an operator reading a captured response sees why.
     */
    private static Mono<Void> deny(ServerWebExchange exchange, HttpStatus status, String reasonCode) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String body = "{\"reason_code\":\"" + ReasonCodes.orUnspecified(reasonCode) + "\"}";
        DataBuffer buffer = exchange.getResponse().bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}