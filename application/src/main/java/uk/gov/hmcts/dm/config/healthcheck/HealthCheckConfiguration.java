package uk.gov.hmcts.dm.config.healthcheck;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.system.DiskSpaceHealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.File;


/**
 * Created by pawel on 10/07/2017.
 */
@Configuration
public class HealthCheckConfiguration {

    @Bean
    DiskSpaceHealthIndicator diskSpaceHealthIndicator(@Value("${health.disk.threshold}") long threshold) {
        return new DiskSpaceHealthIndicator(new File("/"), threshold);
    }

}
