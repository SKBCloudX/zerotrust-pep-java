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
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Checks that the enforcement point denies whenever it cannot obtain a decision.
 *
 * <h2>Why this is the test that matters most</h2>
 *
 * Every other failure in this library degrades gracefully. This one does not: an enforcement
 * point that lets traffic through when its decision point is unreachable is worse than having
 * no enforcement point at all, because the deployment believes it is protected. Outages are
 * exactly when an attacker benefits from the gap, and exactly when a naive error branch says
 * "just let it through so the service stays up".
 *
 * <p>Each case therefore asserts on the backend hit count as well as the status. A 403 that
 * still proxied the request is indistinguishable from a real denial to the caller.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = FailClosedTest.TestGateway.class)
class FailClosedTest {

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
        pem = jwt.writePublicKeyPem(Files.createTempDirectory("zt-pep-failclosed"));
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
        // Keep the unreachable case short; the point is the outcome, not the wait.
        registry.add("zt.pep.timeout", () -> "2s");
    }

    private String token() throws Exception {
        return jwt.validToken("alice", List.of("user"), ISSUER, AUDIENCE);
    }

    private WebTestClient.ResponseSpec call() throws Exception {
        return client.mutate().responseTimeout(Duration.ofSeconds(20)).build()
                .get().uri("/api/v1/items")
                .header("Authorization", "Bearer " + token())
                .exchange();
    }

    @Test
    void anExplicitDenyIsEnforcedAndExplained() throws Exception {
        decisions.respondWith(200,
                "{\"decision\":false,\"context\":{\"id\":\"d-2\",\"reason_code\":\"SUBJECT_SUSPENDED\"}}");
        int before = backend.hitCount();

        call().expectStatus().isForbidden()
                .expectBody().jsonPath("$.reason_code").isEqualTo("SUBJECT_SUSPENDED");

        assertThat(backend.hitCount()).isEqualTo(before);
    }

    @Test
    void aDenyWithNoReasonStillRecordsOne() throws Exception {
        // An audit line reading only "denied" cannot be investigated later.
        decisions.respondWith(200, "{\"decision\":false,\"context\":{\"id\":\"d-3\"}}");
        int before = backend.hitCount();

        call().expectStatus().isForbidden()
                .expectBody().jsonPath("$.reason_code").isEqualTo("UNSPECIFIED");

        assertThat(backend.hitCount()).isEqualTo(before);
    }

    @Test
    void aReasonThisBuildHasNeverSeenIsStillADeny() throws Exception {
        // The published vocabulary grows without a major version bump. A newer decision point
        // must not be able to turn a denial into a parse error here.
        decisions.respondWith(200,
                "{\"decision\":false,\"context\":{\"id\":\"d-4\",\"reason_code\":\"INVENTED_LATER\"}}");
        int before = backend.hitCount();

        call().expectStatus().isForbidden()
                .expectBody().jsonPath("$.reason_code").isEqualTo("INVENTED_LATER");

        assertThat(backend.hitCount()).isEqualTo(before);
    }

    @Test
    void aDecisionPointReturningAnErrorDenies() throws Exception {
        decisions.respondWith(500, "{\"error\":\"boom\"}");
        int before = backend.hitCount();

        call().expectStatus().isForbidden();

        assertThat(backend.hitCount())
                .as("a 500 from the decision point is not permission to proceed")
                .isEqualTo(before);
    }

    @Test
    void anUnreadableDecisionBodyDenies() throws Exception {
        decisions.respondWith(200, "this is not json");
        int before = backend.hitCount();

        call().expectStatus().isForbidden();

        assertThat(backend.hitCount()).isEqualTo(before);
    }

    @Test
    void aDecisionPointThatNeverAnswersDenies() throws Exception {
        decisions.goSilent();
        int before = backend.hitCount();

        call().expectStatus().isForbidden();

        assertThat(backend.hitCount())
                .as("a hung decision point must not become an open door")
                .isEqualTo(before);

        decisions.respondWith(200, "{\"decision\":true,\"context\":{\"id\":\"d-5\"}}");
    }
}