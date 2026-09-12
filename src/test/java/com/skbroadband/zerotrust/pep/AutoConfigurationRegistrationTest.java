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

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.web.reactive.function.client.WebClientAutoConfiguration;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the library actually registers itself in a host application.
 *
 * <p>This is the failure this project exists to avoid. The filter it replaces was annotated
 * {@code @Component}, which works only inside its own application's component scan. Extracted
 * into a library under a different package, that annotation registers nothing: the jar sits on
 * the classpath and no request is ever authorized. The gateway looks healthy and enforces
 * nothing, which is worse than failing to start.
 */
class AutoConfigurationRegistrationTest {

    private final ReactiveWebApplicationContextRunner runner =
            new ReactiveWebApplicationContextRunner()
                    // WebClientAutoConfiguration supplies WebClient.Builder. A Spring Cloud
                    // Gateway is a WebFlux application, so it is always present in a real host;
                    // including it here keeps the test on the same registration chain rather
                    // than a narrower one that would hide a missing dependency.
                    .withConfiguration(AutoConfigurations.of(
                            WebClientAutoConfiguration.class, PepAutoConfiguration.class));

    @Test
    void registrationFileNamesTheAutoConfiguration() throws Exception {
        Path imports = Path.of("src/main/resources/META-INF/spring/"
                + "org.springframework.boot.autoconfigure.AutoConfiguration.imports");
        assertThat(imports).exists();
        assertThat(Files.readString(imports).trim())
                .isEqualTo(PepAutoConfiguration.class.getName());

        // Boot 2.x reads spring.factories instead. One artifact has to serve both generations.
        Path factories = Path.of("src/main/resources/META-INF/spring.factories");
        assertThat(factories).exists();
        assertThat(Files.readString(factories))
                .contains(PepAutoConfiguration.class.getName());
    }

    @Test
    void addingTheDependencyAloneChangesNothing() {
        // No zt.pep.enabled -> no beans. An operator must be able to deploy the jar and turn
        // enforcement on as a separate, reversible step.
        runner.run(context -> assertThat(context).doesNotHaveBean(PepGlobalFilter.class));
    }

    @Test
    void globalIsTheDefaultShapeWhenEnabled(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path pem = writeKey(tmp);
        runner.withPropertyValues(
                        "zt.pep.enabled=true",
                        "zt.pep.decision-url=https://example.invalid/access/v1/evaluation",
                        "zt.pep.jwt-public-key-path=" + pem)
                .run(context -> {
                    assertThat(context).hasSingleBean(PepGlobalFilter.class);
                    assertThat(context).doesNotHaveBean(PepFilterFactory.class);
                });
    }

    @Test
    void perRouteShapeIsSelectable(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path pem = writeKey(tmp);
        runner.withPropertyValues(
                        "zt.pep.enabled=true",
                        "zt.pep.mode=per-route",
                        "zt.pep.decision-url=https://example.invalid/access/v1/evaluation",
                        "zt.pep.jwt-public-key-path=" + pem)
                .run(context -> {
                    assertThat(context).hasSingleBean(PepFilterFactory.class);
                    assertThat(context).doesNotHaveBean(PepGlobalFilter.class);
                });
    }

    /** Writes a throwaway RSA public key so the verifier bean can be built. */
    private static Path writeKey(Path dir) throws Exception {
        var gen = java.security.KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        byte[] der = gen.generateKeyPair().getPublic().getEncoded();
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END PUBLIC KEY-----\n";
        Path f = dir.resolve("jwt_pub.pem");
        Files.writeString(f, pem);
        return f;
    }

    @Test
    void publishedVocabularyIsNotAClosedEnum() {
        // Reason codes are String constants. If this ever becomes an enum, a deployment that
        // adds a reason turns every denial into a parse failure — and a denial that cannot be
        // read never reaches the fail-closed path cleanly.
        List<Class<?>> notEnums = List.of(String.class);
        assertThat(ReasonCodes.SUBJECT_SUSPENDED.getClass()).isIn(notEnums);
    }
}