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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.PublicKey;

/**
 * Registers the enforcement filter in the host gateway.
 *
 * <h2>Why this class exists instead of {@code @Component}</h2>
 *
 * A {@code @Component} is only found by the host application's component scan, which covers
 * the package of its own {@code @SpringBootApplication} and below. This library lives under
 * {@code com.skbroadband.zerotrust.pep}, which is not under anyone else's application
 * package — so annotating the filter as a component would do nothing at all. The jar would be
 * on the classpath and no filter would ever run.
 *
 * <p>Spring Boot instead reads
 * {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}
 * from every jar on the classpath and instantiates the configuration classes listed there.
 * That is how a dependency can register beans in an application whose source it never sees,
 * and it is the reason this library can be adopted by adding one block to a {@code pom.xml}.
 *
 * <p>Boot 2.x reads {@code META-INF/spring.factories} instead, and that file ships too. Boot 3
 * ignores the auto-configuration entries in {@code spring.factories}, so carrying both costs
 * nothing.
 *
 * <p><strong>Shipping the file is not a claim that Boot 2 works.</strong> Class files target
 * Java 17, so a Boot 2 application on Java 8 or 11 cannot load them at all, and nothing here
 * has ever been run on Boot 2. Treat Boot 2.7 on Java 17 as untested rather than supported —
 * see the README.
 *
 * <h2>Off by default</h2>
 *
 * Nothing is registered unless {@code zt.pep.enabled=true}. Adding the dependency must not
 * change how an existing gateway behaves — an operator has to be able to deploy the jar and
 * turn enforcement on as a separate, reversible step.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(PepProperties.class)
@ConditionalOnProperty(prefix = "zt.pep", name = "enabled", havingValue = "true")
public class PepAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public DecisionClient ztPepDecisionClient(WebClient.Builder builder, PepProperties props) {
        return new DecisionClient(builder, props);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtVerifier ztPepJwtVerifier(PepProperties props) throws Exception {
        PublicKey key = JwtVerifier.loadPublicKey(props.getJwtPublicKeyPath());
        return new JwtVerifier(key, props.getJwtIssuer(), props.getJwtAudience());
    }

    @Bean
    @ConditionalOnMissingBean
    public PepEnforcement ztPepEnforcement(DecisionClient decisions, JwtVerifier jwt) {
        return new PepEnforcement(decisions, jwt);
    }

    /**
     * Registers the global filter unless the deployment asked for per-route.
     *
     * <p>{@code matchIfMissing} is true so the default shape is the one that protects every
     * route. Defaulting to per-route would mean a gateway that adopted this library and set
     * nothing else would enforce nothing.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "zt.pep", name = "mode",
            havingValue = "global", matchIfMissing = true)
    static class GlobalMode {
        @Bean
        @ConditionalOnMissingBean
        PepGlobalFilter ztPepGlobalFilter(PepEnforcement enforcement, PepProperties props) {
            return new PepGlobalFilter(enforcement, props.getOrder());
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "zt.pep", name = "mode", havingValue = "per-route")
    static class PerRouteMode {
        @Bean
        @ConditionalOnMissingBean
        PepFilterFactory ztPepFilterFactory(@Autowired PepEnforcement enforcement) {
            return new PepFilterFactory(enforcement);
        }
    }
}