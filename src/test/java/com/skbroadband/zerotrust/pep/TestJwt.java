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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Mints real RS256 tokens for the end-to-end tests.
 *
 * <p>The tokens are genuinely signed rather than stubbed, so the tests exercise
 * {@link JwtVerifier} on the same path production takes. A test that bypassed signature
 * verification would still pass if the verifier were removed from the chain entirely.
 */
final class TestJwt {

    private final KeyPair keyPair;

    TestJwt() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        this.keyPair = gen.generateKeyPair();
    }

    /** Writes the public half as PEM where {@link JwtVerifier} expects to read it. */
    Path writePublicKeyPem(Path dir) throws Exception {
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                        .encodeToString(keyPair.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n";
        Path f = dir.resolve("jwt_pub.pem");
        Files.writeString(f, pem);
        return f;
    }

    String validToken(String subject, List<String> roles, String issuer, String audience) throws Exception {
        long now = Instant.now().getEpochSecond();
        return sign("RS256", claims(subject, roles, issuer, audience, now - 10, now + 300));
    }

    String expiredToken(String subject, String issuer, String audience) throws Exception {
        long now = Instant.now().getEpochSecond();
        // Well past the verifier's 60s clock skew allowance.
        return sign("RS256", claims(subject, List.of("user"), issuer, audience, now - 7200, now - 3600));
    }

    String wrongIssuerToken(String subject, String audience) throws Exception {
        long now = Instant.now().getEpochSecond();
        return sign("RS256", claims(subject, List.of("user"), "https://attacker.example", audience, now - 10, now + 300));
    }

    /**
     * A token whose header claims {@code none}.
     *
     * <p>The classic JWT forgery: strip the signature and tell the verifier not to check one.
     * The algorithm allowlist has to reject this before it looks at anything else.
     */
    String algNoneToken(String subject, String issuer, String audience) {
        long now = Instant.now().getEpochSecond();
        String header = b64("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = b64(claims(subject, List.of("admin"), issuer, audience, now - 10, now + 300));
        return header + "." + payload + ".";
    }

    /** A well-formed token signed by a different key — signature must fail. */
    String foreignKeyToken(String subject, String issuer, String audience) throws Exception {
        TestJwt other = new TestJwt();
        return other.validToken(subject, List.of("admin"), issuer, audience);
    }

    private static String claims(String sub, List<String> roles, String iss, String aud, long nbf, long exp) {
        String rolesJson = roles.stream()
                .map(r -> "\"" + r + "\"")
                .collect(Collectors.joining(",", "[", "]"));
        return "{\"sub\":\"" + sub + "\",\"roles\":" + rolesJson
                + ",\"iss\":\"" + iss + "\",\"aud\":\"" + aud + "\""
                + ",\"nbf\":" + nbf + ",\"exp\":" + exp + "}";
    }

    private String sign(String alg, String claimsJson) throws Exception {
        String header = b64("{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}");
        String payload = b64(claimsJson);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        sig.update((header + "." + payload).getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign());
        return header + "." + payload + "." + signature;
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }
}