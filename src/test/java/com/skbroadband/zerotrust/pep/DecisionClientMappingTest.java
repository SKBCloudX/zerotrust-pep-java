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
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Locks the request mapping against the decision API's flattening rules.
 *
 * <p>These are not style assertions. Each one corresponds to a way the mapping has actually
 * gone wrong, and every failure mode was partial — some roles allowed, others denied — which
 * is why none of them were caught by a stub server. A stub echoes whatever it is sent, so it
 * agrees with any mapping, correct or not.
 */
class DecisionClientMappingTest {

    private DecisionClient client() {
        PepProperties props = new PepProperties();
        props.setDecisionUrl("https://example.invalid/access/v1/evaluation");
        return new DecisionClient(WebClient.builder(), props);
    }

    @Test
    void pathIsCarriedWhereThePolicyReadsIt() {
        Map<String, Object> body = client()
                .buildRequest("alice", List.of("user"), "/api/v1/items", "GET");

        @SuppressWarnings("unchecked")
        Map<String, Object> resource = (Map<String, Object>) body.get("resource");
        @SuppressWarnings("unchecked")
        Map<String, Object> props = (Map<String, Object>) resource.get("properties");

        // resource.id is required by the API, but it lands nested at input.resource.id
        // and the policy bundle reads input.path. Both must be present.
        assertEquals("/api/v1/items", resource.get("id"), "resource.id is required");
        assertEquals("/api/v1/items", props.get("path"),
                "resource.properties.path is what reaches input.path");
    }

    @Test
    void subjectIdIsSentOnceOnly() {
        Map<String, Object> body = client()
                .buildRequest("alice", List.of("user"), "/x", "GET");

        @SuppressWarnings("unchecked")
        Map<String, Object> subject = (Map<String, Object>) body.get("subject");
        assertEquals("alice", subject.get("id"));

        @SuppressWarnings("unchecked")
        Map<String, Object> props = (Map<String, Object>) subject.get("properties");
        assertFalse(props != null && props.containsKey("user_id"),
                "subject.id already becomes input.user_id; a duplicate diverges when it is blank");
    }

    @Test
    void rolesRideAsExtensionProperties() {
        Map<String, Object> body = client()
                .buildRequest("alice", List.of("user", "admin"), "/x", "GET");

        @SuppressWarnings("unchecked")
        Map<String, Object> subject = (Map<String, Object>) body.get("subject");
        @SuppressWarnings("unchecked")
        Map<String, Object> props = (Map<String, Object>) subject.get("properties");
        assertEquals(List.of("user", "admin"), props.get("roles"),
                "subject.properties.roles reaches input.roles");
    }

    @Test
    void emptyRolesAreOmittedRatherThanSentBlank() {
        Map<String, Object> body = client().buildRequest("alice", List.of(), "/x", "GET");

        @SuppressWarnings("unchecked")
        Map<String, Object> subject = (Map<String, Object>) body.get("subject");
        assertFalse(subject.containsKey("properties"),
                "absence and blank mean different things to a policy; send neither rather than empty");
    }

    @Test
    void methodIsLowercased() {
        Map<String, Object> body = client().buildRequest("alice", List.of("user"), "/x", "GET");

        @SuppressWarnings("unchecked")
        Map<String, Object> action = (Map<String, Object>) body.get("action");
        assertEquals("get", action.get("name"));
    }

    @Test
    void requiredFieldsAreNeverBlank() {
        Map<String, Object> body = client().buildRequest("alice", null, "", "");

        @SuppressWarnings("unchecked")
        Map<String, Object> resource = (Map<String, Object>) body.get("resource");
        @SuppressWarnings("unchecked")
        Map<String, Object> action = (Map<String, Object>) body.get("action");
        assertEquals("/", resource.get("id"), "a blank required field is rejected as a bad request");
        assertEquals("get", action.get("name"));
    }

    @Test
    void unknownReasonCodesSurviveUnchanged() {
        // The published vocabulary grows without a major version bump. A code this build has
        // never seen must still read as a denial, not as a parse failure.
        assertEquals("SOMETHING_ADDED_LATER",
                ReasonCodes.orUnspecified("SOMETHING_ADDED_LATER"));
        assertEquals(ReasonCodes.UNSPECIFIED, ReasonCodes.orUnspecified(""));
        assertEquals(ReasonCodes.UNSPECIFIED, ReasonCodes.orUnspecified(null));
        assertTrue(ReasonCodes.SUBJECT_SUSPENDED.equals("SUBJECT_SUSPENDED"));
    }
}