package com.sp.npf.key.client.spring;

import javax.servlet.Filter;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import com.sp.npf.key.client.KeyClient;
import com.sp.npf.key.client.KeyClientConfig;

@Configuration
@ConditionalOnClass(KeyClient.class)
@ConditionalOnProperty(prefix = "npf.key.client", name = "base-url")
@EnableConfigurationProperties(NpfKeyClientProperties.class)
public class KeyClientAutoConfiguration {

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean
    public KeyClient keyClient(NpfKeyClientProperties props) {
        KeyClient client = new KeyClient(new KeyClientConfig()
                .baseUrl(props.getBaseUrl())
                .clientId(props.getClientId())
                .refreshSeconds(props.getRefreshSeconds())
                .jitterSeconds(props.getJitterSeconds()));
        client.start();
        return client;
    }

    @Configuration
    @ConditionalOnClass(Filter.class)
    @ConditionalOnProperty(prefix = "npf.key.client", name = "verify-key-name")
    static class VerifyFilterConfiguration {

        @Bean
        public FilterRegistrationBean<KeyVerifyFilter> keyVerifyFilter(KeyClient client, NpfKeyClientProperties props) {
            FilterRegistrationBean<KeyVerifyFilter> reg = new FilterRegistrationBean<>();
            reg.setFilter(new KeyVerifyFilter(client, props.getVerifyKeyName()));
            reg.addUrlPatterns(props.getVerifyPaths().toArray(new String[0]));
            reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
            return reg;
        }
    }
}
