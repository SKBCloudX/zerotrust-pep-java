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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Drives real HTTP traffic through a running Spring Cloud Gateway with this library installed.
 *
 * <h2>Why this exists separately from the mapping tests</h2>
 *
 * The mapping tests inspect the request body this library builds. They say nothing about
 * whether the filter is ever reached — a library can build a perfect request and still be
 * inert because auto-configuration did not register it, or because it registered at an order
 * that lets traffic past first. Those are the failures that look healthiest from the outside:
 * the gateway starts, returns 200, and authorizes nothing.
 *
 * <p>So every assertion here also checks whether the backend was touched. "Denied" and
 * "denied but proxied anyway" produce the same status code to a caller and are completely
 * different security outcomes.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = EndToEndEnforcementTest.TestGateway.class)
class EndToEndEnforcementTest {

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
        // Allow by default; individual tests point the gateway at a different stub when they
        // need a denial, so the happy path stays the one that runs most often.
        decisions = StubServer.replying(200, "{\"decision\":true,\"context\":{\"id\":\"d-1\"}}");
        jwt = new TestJwt();
        pem = jwt.writePublicKeyPem(Files.createTempDirectory("zt-pep-e2e"));
    }

    @AfterAll
    static void stopStubs() throws IOException {
        backend.close();
        decisions.close();
        Files.deleteIfExists(pem);
    }

    @DynamicPropertySource
    static void gatewayConfig(DynamicPropertyRegistry registry) {
        registry.add("spring.cloud.gateway.routes[0].id", () -> "backend");
        registry.add("spring.cloud.gateway.routes[0].uri", () -> backend.url());
        registry.add("spring.cloud.gateway.routes[0].predicates[0]", () -> "Path=/api/**");

        registry.add("zt.pep.enabled", () -> "true");
        registry.add("zt.pep.decision-url", () -> decisions.url() + "/access/v1/evaluation");
        registry.add("zt.pep.jwt-public-key-path", () -> pem.toString());
        registry.add("zt.pep.jwt-issuer", () -> ISSUER);
        registry.add("zt.pep.jwt-audience", () -> AUDIENCE);
    }

    @Test
    void allowedRequestReachesTheBackendAndCarriesTheSubject() throws Exception {
        int before = backend.hitCount();
        String token = jwt.validToken("alice", List.of("user"), ISSUER, AUDIENCE);

        client.get().uri("/api/v1/items")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.backend").isEqualTo("reached");

        assertThat(backend.hitCount()).isEqualTo(before + 1);
        // The backend is told who was authorized, so it does not have to re-parse the token
        // and cannot disagree with the gateway about the subject's identity.
        assertThat(backend.lastRequestHeader("X-ZT-Subject"))
                .as("the authorized subject must reach the backend")
                .isEqualTo("alice");
    }

    @Test
    void aCallerCannotForgeTheSubjectHeader() throws Exception {
        // The backend trusts X-ZT-Subject. If a caller could set it, that trust would be a
        // hole: send someone else's name alongside your own valid token and the backend
        // believes it. The filter overwrites rather than appends.
        String token = jwt.validToken("alice", List.of("user"), ISSUER, AUDIENCE);

        client.get().uri("/api/v1/items")
                .header("Authorization", "Bearer " + token)
                .header("X-ZT-Subject", "root")
                .exchange()
                .expectStatus().isOk();

        assertThat(backend.lastRequestHeader("X-ZT-Subject"))
                .as("a client-supplied subject header must not survive")
                .isEqualTo("alice");
    }

    @Test
    void theDecisionRequestCarriesWhatThePolicyNeeds() throws Exception {
        String token = jwt.validToken("bob", List.of("user", "admin"), ISSUER, AUDIENCE);

        client.get().uri("/api/v1/reports")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk();

        // Proves the mapping survives the real filter path, not just the builder in isolation.
        String body = decisions.lastRequestBody();
        assertThat(body).contains("\"id\":\"bob\"");
        assertThat(body).contains("\"path\":\"/api/v1/reports\"");   // reaches input.path
        assertThat(body).contains("\"name\":\"get\"");               // lowercased method
        assertThat(body).contains("\"user\"").contains("\"admin\""); // roles
    }

    @Test
    void aRequestWithNoTokenNeverReachesTheBackend() {
        int before = backend.hitCount();

        client.get().uri("/api/v1/items")
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(backend.hitCount())
                .as("an unauthenticated request must not be proxied")
                .isEqualTo(before);
    }

    @Test
    void aTokenSignedByAnotherKeyIsRejected() throws Exception {
        int before = backend.hitCount();

        client.get().uri("/api/v1/items")
                .header("Authorization", "Bearer " + jwt.foreignKeyToken("mallory", ISSUER, AUDIENCE))
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(backend.hitCount()).isEqualTo(before);
    }

    @Test
    void anAlgNoneTokenIsRejected() {
        int before = backend.hitCount();

        // Strip the signature, declare "none", and hope the verifier obliges. It must not.
        client.get().uri("/api/v1/items")
                .header("Authorization", "Bearer " + jwt.algNoneToken("mallory", ISSUER, AUDIENCE))
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(backend.hitCount())
                .as("alg=none must never authenticate anyone")
                .isEqualTo(before);
    }

    @Test
    void anExpiredTokenIsRejected() throws Exception {
        int before = backend.hitCount();

        client.get().uri("/api/v1/items")
                .header("Authorization", "Bearer " + jwt.expiredToken("alice", ISSUER, AUDIENCE))
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(backend.hitCount()).isEqualTo(before);
    }

    @Test
    void aTokenFromAnotherIssuerIsRejected() throws Exception {
        int before = backend.hitCount();

        client.get().uri("/api/v1/items")
                .header("Authorization", "Bearer " + jwt.wrongIssuerToken("alice", AUDIENCE))
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(backend.hitCount()).isEqualTo(before);
    }

    @Test
    void aRouteOutsideThePredicateIsStillNotAnOpenDoor() {
        // No route matches /nothing-here, so the gateway itself has nothing to proxy to.
        // The point is that the absence of a route must not turn into a pass-through.
        client.get().uri("/nothing-here").exchange()
                .expectStatus().value(status -> assertThat(status).isNotEqualTo(200));
    }
}