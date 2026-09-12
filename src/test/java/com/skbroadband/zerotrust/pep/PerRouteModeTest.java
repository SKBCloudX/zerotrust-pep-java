/*
 * Copyright 2026 SK Broadband Co., Ltd. (Cloud X Dev. Team). All rights reserved.
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

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Confirms what per-route mode does — including the part that is easy to deploy by accident.
 *
 * <p>Per-route enforcement protects only the routes that name the filter. That is the point of
 * the mode, and it is also its hazard: a route added later without the filter is simply
 * unprotected, and nothing about the gateway's behaviour says so. The README recommends
 * {@code global} for that reason, and this test pins the trade-off in place so nobody has to
 * discover it in production.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = PerRouteModeTest.TestGateway.class)
class PerRouteModeTest {

    @SpringBootApplication
    static class TestGateway {
    }

    private static final String ISSUER = "https://iam.test.local";
    private static final String AUDIENCE = "test-api";

    private static StubServer backend;
    private static StubServer decisions;
    private static TestJwt jwt;
    private static Path pem;

    @Autowired
    private WebTestClient client;

    @BeforeAll
    static void startStubs() throws Exception {
        backend = StubServer.replying(200, "{\"backend\":\"reached\"}");
        decisions = StubServer.replying(200, "{\"decision\":true,\"context\":{\"id\":\"d-1\"}}");
        jwt = new TestJwt();
        pem = jwt.writePublicKeyPem(Files.createTempDirectory("zt-pep-perroute"));
    }

    @AfterAll
    static void stopStubs() throws IOException {
        backend.close();
        decisions.close();
        Files.deleteIfExists(pem);
    }

    @DynamicPropertySource
    static void gatewayConfig(DynamicPropertyRegistry registry) {
        // Guarded: names the filter.
        registry.add("spring.cloud.gateway.routes[0].id", () -> "guarded");
        registry.add("spring.cloud.gateway.routes[0].uri", () -> backend.url());
        registry.add("spring.cloud.gateway.routes[0].predicates[0]", () -> "Path=/guarded/**");
        registry.add("spring.cloud.gateway.routes[0].filters[0]", () -> "ZeroTrustPep");

        // Open: does not. Deliberately present, to show what the mode leaves behind.
        registry.add("spring.cloud.gateway.routes[1].id", () -> "open");
        registry.add("spring.cloud.gateway.routes[1].uri", () -> backend.url());
        registry.add("spring.cloud.gateway.routes[1].predicates[0]", () -> "Path=/open/**");

        registry.add("zt.pep.enabled", () -> "true");
        registry.add("zt.pep.mode", () -> "per-route");
        registry.add("zt.pep.decision-url", () -> decisions.url() + "/access/v1/evaluation");
        registry.add("zt.pep.jwt-public-key-path", () -> pem.toString());
        registry.add("zt.pep.jwt-issuer", () -> ISSUER);
        registry.add("zt.pep.jwt-audience", () -> AUDIENCE);
    }

    @Test
    void theNamedRouteIsEnforced() {
        int before = backend.hitCount();

        client.get().uri("/guarded/thing").exchange()
                .expectStatus().isUnauthorized();

        assertThat(backend.hitCount()).isEqualTo(before);
    }

    @Test
    void theNamedRouteStillPassesAValidRequest() throws Exception {
        int before = backend.hitCount();

        client.get().uri("/guarded/thing")
                .header("Authorization", "Bearer " + jwt.validToken("alice", java.util.List.of("user"), ISSUER, AUDIENCE))
                .exchange()
                .expectStatus().isOk();

        assertThat(backend.hitCount()).isEqualTo(before + 1);
    }

    @Test
    void anUnnamedRouteIsNotProtected() {
        int before = backend.hitCount();

        // No token, no filter, straight through. This is per-route mode working as designed —
        // which is precisely why global is the default and the recommendation.
        client.get().uri("/open/thing").exchange()
                .expectStatus().isOk();

        assertThat(backend.hitCount())
                .as("per-route mode leaves unnamed routes open; deploy it knowing that")
                .isEqualTo(before + 1);
    }
}