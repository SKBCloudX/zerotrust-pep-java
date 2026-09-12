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

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Asks the decision API whether one HTTP request is allowed.
 *
 * <p>The enforcement point does not decide anything; it asks and enforces. Keeping the two
 * apart is what lets the decision point change its policy engine without this library
 * caring, and what lets a deployment point this library at a different decision point.
 */
public class DecisionClient {

    /** Result of one authorization query. */
    public record Decision(boolean allow, String reasonCode) {
    }

    private final WebClient http;
    private final String url;
    private final String token;
    private final Duration timeout;

    public DecisionClient(WebClient.Builder builder, PepProperties props) {
        this.http = builder.build();
        this.url = props.getDecisionUrl();
        this.token = props.getDecisionToken();
        this.timeout = props.getTimeout();
    }

    /**
     * Builds the request body for one HTTP request.
     *
     * <h2>Why the path is sent twice</h2>
     *
     * The decision API flattens the request into the policy engine's input, and it does so
     * <strong>asymmetrically</strong>:
     *
     * <pre>
     *   keys the API knows (target, protocol)  -&gt; promoted, but NESTED   input.resource.target
     *   keys the API does not know (path, ...) -&gt; carried through, TOP-LEVEL  input.path
     * </pre>
     *
     * The more familiar the key, the deeper it lands. That is the opposite of what anyone
     * guesses, and it caused a real defect: sending the path only as {@code resource.id} put
     * it at {@code input.resource.id}, while the policy bundle reads {@code input.path}. The
     * bundle's path check silently never matched, so roles whose rules ignore the path were
     * allowed and roles whose rules check it were denied — a partial failure, which is far
     * harder to notice than a total one.
     *
     * <p>So the path goes in {@code resource.id} (it is required there) <em>and</em> in
     * {@code resource.properties.path}, which is what reaches {@code input.path}.
     *
     * <h2>Why the subject id is sent once</h2>
     *
     * {@code subject.id} already becomes {@code input.user_id}. Sending it a second time as an
     * extension property looks harmless — and is, right up until {@code subject.id} is empty.
     * Extension properties are laid down first and core fields overwrite them, but an empty
     * core field is omitted entirely (absence and blank mean different things to a policy), so
     * the stale extension value would survive and be used. One source only.
     *
     * <h2>Why empty values are omitted</h2>
     *
     * Absence is not the same as blank. A blank value matches no branch and reads as a denial;
     * an absent one reads as "not supplied". Sending {@code ""} to mean "we don't know" flips
     * decisions.
     */
    Map<String, Object> buildRequest(String subjectId, List<String> roles, String path, String method) {
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("type", "user");
        subject.put("id", subjectId);
        if (roles != null && !roles.isEmpty()) {
            subject.put("properties", Map.of("roles", roles));
        }

        String safePath = (path == null || path.isEmpty()) ? "/" : path;
        Map<String, Object> resource = new LinkedHashMap<>();
        resource.put("type", "http");
        resource.put("id", safePath);
        resource.put("properties", Map.of("path", safePath));

        String safeMethod = (method == null || method.isEmpty())
                ? "get" : method.toLowerCase(Locale.ROOT);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("subject", subject);
        body.put("resource", resource);
        body.put("action", Map.of("name", safeMethod));
        return body;
    }

    /**
     * Queries the decision API.
     *
     * <p>Any failure to obtain a decision — transport error, non-2xx status, unreadable body,
     * timeout — completes as a denial rather than an error, so callers cannot accidentally let
     * a request through by forgetting an error branch. The reason is recorded so the audit
     * trail says why.
     */
    public Mono<Decision> authorize(String subjectId, List<String> roles, String path, String method) {
        if (url == null || url.isBlank()) {
            return Mono.just(new Decision(false, ReasonCodes.UNSPECIFIED));
        }
        WebClient.RequestBodySpec spec = http.post()
                .uri(url)
                .contentType(MediaType.APPLICATION_JSON);
        if (token != null && !token.isBlank()) {
            spec = spec.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        return spec.bodyValue(buildRequest(subjectId, roles, path, method))
                .retrieve()
                .bodyToMono(Map.class)
                .timeout(timeout)
                .map(DecisionClient::parse)
                .onErrorReturn(new Decision(false, ReasonCodes.UNSPECIFIED));
    }

    /**
     * Reads the decision response.
     *
     * <p>The reason code is kept as a string even when this build does not recognise it. The
     * published vocabulary grows without a major version bump, so rejecting unknown codes
     * would turn a perfectly ordinary denial into a parse failure. See {@link ReasonCodes}.
     */
    @SuppressWarnings("unchecked")
    private static Decision parse(Map<?, ?> body) {
        boolean allow = Boolean.TRUE.equals(body.get("decision"));
        String reason = "";
        Object ctx = body.get("context");
        if (ctx instanceof Map<?, ?> ctxMap) {
            Object code = ctxMap.get("reason_code");
            if (code != null) {
                reason = code.toString();
            }
        }
        return new Decision(allow, allow ? reason : ReasonCodes.orUnspecified(reason));
    }
}