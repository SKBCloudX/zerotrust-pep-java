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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Hardened RS256 JWT verifier: algorithm allowlist (RS256 only), signature, and
 * iss/aud/nbf/exp with clock skew. Every failure throws (fail-closed).
 */
public class JwtVerifier {

    public static class JwtException extends Exception {
        public JwtException(String m) { super(m); }
    }

    public static class Claims {
        public final String sub;
        public final List<String> roles;
        public Claims(String sub, List<String> roles) { this.sub = sub; this.roles = roles; }
    }

    private static final ObjectMapper M = new ObjectMapper();
    private static final long SKEW = 60;

    private final PublicKey pub;
    private final String wantIss;
    private final String wantAud;

    public JwtVerifier(PublicKey pub, String iss, String aud) {
        this.pub = pub; this.wantIss = iss; this.wantAud = aud;
    }

    public static PublicKey loadPublicKey(String pemPath) throws Exception {
        String pem = Files.readString(Path.of(pemPath))
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
        byte[] der = Base64.getMimeDecoder().decode(pem);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    public Claims verify(String token, long nowEpoch) throws JwtException {
        String[] p = token.split("[.]");
        if (p.length != 3) throw new JwtException("malformed");
        Base64.Decoder dec = Base64.getUrlDecoder();
        try {
            JsonNode hdr = M.readTree(dec.decode(p[0]));
            if (!"RS256".equals(hdr.path("alg").asText()))
                throw new JwtException("algorithm not allowed: " + hdr.path("alg").asText());

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(pub);
            sig.update((p[0] + "." + p[1]).getBytes());
            if (!sig.verify(dec.decode(p[2]))) throw new JwtException("signature verification failed");

            JsonNode c = M.readTree(dec.decode(p[1]));
            if (wantIss != null && !wantIss.isEmpty() && !wantIss.equals(c.path("iss").asText()))
                throw new JwtException("issuer mismatch");
            if (wantAud != null && !wantAud.isEmpty() && !wantAud.equals(c.path("aud").asText()))
                throw new JwtException("audience mismatch");
            long exp = c.path("exp").asLong(0);
            if (exp > 0 && nowEpoch > exp + SKEW) throw new JwtException("token expired");
            long nbf = c.path("nbf").asLong(0);
            if (nbf > 0 && nowEpoch < nbf - SKEW) throw new JwtException("token not yet valid");

            List<String> roles = new ArrayList<>();
            c.path("roles").forEach(n -> roles.add(n.asText()));
            return new Claims(c.path("sub").asText(), roles);
        } catch (JwtException e) {
            throw e;
        } catch (Exception e) {
            throw new JwtException("malformed: " + e.getMessage());
        }
    }
}