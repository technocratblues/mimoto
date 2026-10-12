package io.mosip.mimoto.config.device;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

@Configuration
public class DeviceAttestationConfig {

    /**
     * Client for Google's OAuth token endpoint and the Play Integrity API, with explicit timeouts
     * so a slow Google call cannot hold a registration request indefinitely.
     */
    @Bean("playIntegrityRestTemplate")
    public RestTemplate playIntegrityRestTemplate(RestTemplateBuilder builder) {
        return builder
                .setConnectTimeout(Duration.ofSeconds(5))
                .setReadTimeout(Duration.ofSeconds(10))
                .build();
    }
}
