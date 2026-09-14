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

/**
 * Deny reason codes published by the decision API.
 *
 * <h2>These are constants, not an enum — on purpose</h2>
 *
 * The published vocabulary is <strong>not a closed set</strong>. Adding a reason code is a
 * non-breaking change on the decision API's side and does not raise its major version; only
 * renaming or removing one is breaking.
 *
 * <p>If this library parsed reason codes into a closed {@code enum}, then the moment a
 * deployment started returning a code this build has never heard of:
 *
 * <pre>
 *   deny response arrives with an unknown reason
 *     -&gt; enum parsing throws
 *     -&gt; the deny is never read as a deny; it surfaces as an internal error
 *     -&gt; the enforcement point does not even reach its fail-closed path cleanly
 * </pre>
 *
 * A denial that cannot be read is worse than an unfamiliar one. So reason codes stay
 * {@code String}, unknown values are accepted, and callers treat anything they do not
 * recognise the same way they treat {@link #UNSPECIFIED}.
 *
 * <p>This matters more than usual here: releases are published to Maven Central, and a
 * published version can never be modified or withdrawn. A closed enum shipped once would
 * keep breaking against future deployments forever.
 *
 * <h2>Only the published vocabulary belongs here</h2>
 *
 * The decision API maps its internal policy-bundle vocabulary onto the published codes
 * below. Internal names (for example the bundle's own {@code USER_SUSPENDED}) must never be
 * added to this class — they are free to change and are not part of any contract.
 */
public final class ReasonCodes {

    /** The subject's account is suspended. */
    public static final String SUBJECT_SUSPENDED = "SUBJECT_SUSPENDED";

    /** The subject is blocked outright. */
    public static final String SUBJECT_BLOCKED = "SUBJECT_BLOCKED";

    /** The request's source was refused (for example a blocked network address). */
    public static final String SOURCE_DENIED = "SOURCE_DENIED";

    /** The device failed a posture requirement. */
    public static final String DEVICE_POSTURE = "DEVICE_POSTURE";

    /** The presented credential was rejected. */
    public static final String CREDENTIAL_REJECTED = "CREDENTIAL_REJECTED";

    /**
     * No specific reason was supplied.
     *
     * <p>Also the value this library substitutes when a denial arrives with an empty reason,
     * so that an audit record never says only "denied" with no cause. Treat an unrecognised
     * code the same way.
     */
    public static final String UNSPECIFIED = "UNSPECIFIED";

    private ReasonCodes() {
    }

    /**
     * Normalises a reason for recording: blank becomes {@link #UNSPECIFIED}.
     *
     * <p>Unknown-but-present codes are returned unchanged. Do not "correct" them to
     * {@code UNSPECIFIED} — the raw value is what an operator needs when diagnosing a denial
     * produced by a newer decision API than this build knows about.
     */
    public static String orUnspecified(String reasonCode) {
        return (reasonCode == null || reasonCode.isBlank()) ? UNSPECIFIED : reasonCode;
    }
}