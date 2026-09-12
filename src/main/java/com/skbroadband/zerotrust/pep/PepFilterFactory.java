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

import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;

/**
 * Applies enforcement to the routes that name it. Selected by {@code zt.pep.mode=per-route}.
 *
 * <p>Routes opt in by name:
 * <pre>
 * filters:
 *   - name: ZeroTrustPep
 * </pre>
 *
 * <p>Per-route mode leaves every unnamed route unprotected, which is the opposite of
 * default-deny. Prefer {@code global} unless the gateway carries routes that genuinely must
 * not be authorized — a health endpoint an external monitor scrapes, for instance.
 */
public class PepFilterFactory extends AbstractGatewayFilterFactory<Object> {

    private final PepEnforcement enforcement;

    PepFilterFactory(PepEnforcement enforcement) {
        super(Object.class);
        this.enforcement = enforcement;
    }

    @Override
    public String name() {
        return "ZeroTrustPep";
    }

    @Override
    public GatewayFilter apply(Object config) {
        return enforcement::enforce;
    }
}