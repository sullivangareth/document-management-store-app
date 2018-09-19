package uk.gov.hmcts.dm.service;

import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

import javax.validation.constraints.NotNull;
import java.time.LocalDateTime;

import static java.time.temporal.ChronoUnit.SECONDS;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric;

class MigrationAuthToken {

    private final String migrateSecret;

    @Getter
    @NotNull
    private final String token;

    @NotNull
    private final LocalDateTime expiry;

    MigrationAuthToken(final String migrateSecret, final Integer tokenSize, final Integer ttlInSeconds) {
        this.migrateSecret = migrateSecret;
        this.token = randomAlphanumeric(tokenSize);
        this.expiry = LocalDateTime.now().plus(ttlInSeconds, SECONDS);
    }

    boolean isValid(String migrateSecret, String token) {
        return StringUtils.equals(this.migrateSecret, migrateSecret)  // checks that migrateSecret agrees
            && StringUtils.equals(this.token, token)  // checks that we have the correct token
            && LocalDateTime.now().isBefore(expiry)  // checks that this token is not expired
            ;
    }
}
