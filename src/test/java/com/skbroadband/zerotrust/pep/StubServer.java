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

import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A throwaway HTTP endpoint used to stand in for the decision API and for a backend.
 *
 * <p>Built on reactor-netty, which is already on the test classpath, so the end-to-end tests
 * add no dependency of their own. That matters: this library's whole compatibility story
 * rests on having nothing but Spring on the classpath, and a test harness that quietly pulled
 * in an HTTP mocking library would make it easy to lose track of that.
 */
final class StubServer implements AutoCloseable {

    private final DisposableServer server;
    private final AtomicReference<String> lastBody = new AtomicReference<>();
    private final AtomicInteger hits = new AtomicInteger();
    /** Mutable so one bound port can play allow, deny and unusable across tests. */
    private final AtomicReference<int[]> status = new AtomicReference<>(new int[]{200});
    private final AtomicReference<String> payload = new AtomicReference<>("{}");
    private final AtomicReference<Boolean> silent = new AtomicReference<>(false);
    private final AtomicReference<java.util.Map<String, String>> lastHeaders =
            new AtomicReference<>(java.util.Map.of());

    private StubServer(DisposableServer server) {
        this.server = server;
    }

    /** Replies with a status and body that later tests may change. */
    static StubServer replying(int status, String body) {
        StubServer[] holder = new StubServer[1];
        DisposableServer s = HttpServer.create().port(0)
                .handle((req, res) -> req.receive().aggregate().asString(StandardCharsets.UTF_8)
                        .defaultIfEmpty("")
                        .flatMap(received -> {
                            StubServer self = holder[0];
                            self.hits.incrementAndGet();
                            self.lastBody.set(received);
                            java.util.Map<String, String> hs = new java.util.LinkedHashMap<>();
                            req.requestHeaders().forEach(e -> hs.put(e.getKey(), e.getValue()));
                            self.lastHeaders.set(hs);
                            if (Boolean.TRUE.equals(self.silent.get())) {
                                return Mono.never();
                            }
                            res.status(self.status.get()[0]);
                            res.header("Content-Type", "application/json");
                            return res.sendString(Mono.just(self.payload.get())).then();
                        }))
                .bindNow();
        holder[0] = new StubServer(s);
        holder[0].status.set(new int[]{status});
        holder[0].payload.set(body);
        return holder[0];
    }

    /** Answer every subsequent call with this status and body. */
    void respondWith(int httpStatus, String body) {
        silent.set(false);
        status.set(new int[]{httpStatus});
        payload.set(body);
    }

    /**
     * Accept connections but never reply.
     *
     * <p>The case a half-broken deployment actually produces — the decision point is up
     * enough to accept a socket and useless beyond that. Harder for a client to handle than
     * a refused connection, and the one most likely to be mishandled into fail-open.
     */
    void goSilent() {
        silent.set(true);
    }

    /**
     * A server that accepts a connection and then drops it without replying.
     *
     * <p>Used to prove the enforcement point fails closed on a decision point that is present
     * but unusable — a subtler case than a refused connection, and the one a half-broken
     * deployment actually produces.
     */
    static StubServer thatNeverAnswers() {
        StubServer[] holder = new StubServer[1];
        DisposableServer s = HttpServer.create().port(0)
                .handle((req, res) -> {
                    holder[0].hits.incrementAndGet();
                    return Mono.never();
                })
                .bindNow();
        holder[0] = new StubServer(s);
        return holder[0];
    }

    String url() {
        return "http://127.0.0.1:" + server.port();
    }

    int port() {
        return server.port();
    }

    /** The body of the most recent request, or null if it was never called. */
    String lastRequestBody() {
        return lastBody.get();
    }

    int hitCount() {
        return hits.get();
    }

    /** Header value from the most recent request, or null. Case-insensitive. */
    String lastRequestHeader(String name) {
        return lastHeaders.get().entrySet().stream()
                .filter(e -> e.getKey().equalsIgnoreCase(name))
                .map(java.util.Map.Entry::getValue)
                .findFirst().orElse(null);
    }

    @Override
    public void close() {
        server.disposeNow();
    }
}