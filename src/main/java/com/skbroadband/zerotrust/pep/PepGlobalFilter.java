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

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/** Applies enforcement to every route. Selected by {@code zt.pep.mode=global}. */
public class PepGlobalFilter implements GlobalFilter, Ordered {

    private final PepEnforcement enforcement;
    private final int order;

    PepGlobalFilter(PepEnforcement enforcement, int order) {
        this.enforcement = enforcement;
        this.order = order;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return enforcement.enforce(exchange, chain);
    }

    @Override
    public int getOrder() {
        return order;
    }
}