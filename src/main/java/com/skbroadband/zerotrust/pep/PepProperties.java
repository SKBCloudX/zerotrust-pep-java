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

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/** Configuration for the enforcement filter, bound from {@code zt.pep.*}. */
@ConfigurationProperties(prefix = "zt.pep")
public class PepProperties {

    /**
     * Whether to register the filter at all.
     *
     * <p>Defaults to {@code false} so that adding the dependency changes nothing until the
     * operator opts in. A gateway that silently starts denying traffic because a library
     * appeared on the classpath is not something anyone can safely roll out.
     */
    private boolean enabled = false;

    /**
     * {@code global} applies enforcement to every route; {@code per-route} registers a named
     * filter that each route opts into.
     *
     * <p>Both exist because the two hand-ported implementations this library replaces had
     * diverged on exactly this point — one was a global filter, the other a per-route factory.
     * Making it configuration rather than a code fork is the whole reason the library exists.
     */
    private Mode mode = Mode.GLOBAL;

    /** Decision API endpoint, for example {@code https://icam.internal/access/v1/evaluation}. */
    private String decisionUrl;

    /** Bearer token for calling the decision API. Leave unset when using mTLS. */
    private String decisionToken;

    /** How long to wait for a decision before failing closed. */
    private Duration timeout = Duration.ofSeconds(3);

    /** Filter order. Enforcement must run before anything that can reach a backend. */
    private int order = -1;

    /** PEM file holding the RSA public key used to verify request JWTs. */
    private String jwtPublicKeyPath;

    /** Expected JWT issuer. Empty disables the check. */
    private String jwtIssuer = "";

    /** Expected JWT audience. Empty disables the check. */
    private String jwtAudience = "";

    public enum Mode {
        GLOBAL,
        PER_ROUTE
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Mode getMode() {
        return mode;
    }

    public void setMode(Mode mode) {
        this.mode = mode;
    }

    public String getDecisionUrl() {
        return decisionUrl;
    }

    public void setDecisionUrl(String decisionUrl) {
        this.decisionUrl = decisionUrl;
    }

    public String getDecisionToken() {
        return decisionToken;
    }

    public void setDecisionToken(String decisionToken) {
        this.decisionToken = decisionToken;
    }

    public Duration getTimeout() {
        return timeout;
    }

    public void setTimeout(Duration timeout) {
        this.timeout = timeout;
    }

    public int getOrder() {
        return order;
    }

    public void setOrder(int order) {
        this.order = order;
    }

    public String getJwtPublicKeyPath() {
        return jwtPublicKeyPath;
    }

    public void setJwtPublicKeyPath(String jwtPublicKeyPath) {
        this.jwtPublicKeyPath = jwtPublicKeyPath;
    }

    public String getJwtIssuer() {
        return jwtIssuer;
    }

    public void setJwtIssuer(String jwtIssuer) {
        this.jwtIssuer = jwtIssuer;
    }

    public String getJwtAudience() {
        return jwtAudience;
    }

    public void setJwtAudience(String jwtAudience) {
        this.jwtAudience = jwtAudience;
    }
}