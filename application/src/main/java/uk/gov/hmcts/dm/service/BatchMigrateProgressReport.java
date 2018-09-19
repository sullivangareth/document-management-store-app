package uk.gov.hmcts.dm.service;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Data;
import org.springframework.http.HttpStatus;
import uk.gov.hmcts.dm.domain.DocumentContentVersion;

import java.util.List;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;
import static java.util.stream.Collectors.toList;
import static org.springframework.http.HttpStatus.OK;

@Data
@JsonPropertyOrder({BatchMigrateProgressReport.ATTRIBUTE_BEFORE_JOB, BatchMigrateProgressReport.ATTRIBUTE_MIGRATED,
    BatchMigrateProgressReport.ATTRIBUTE_AFTER_JOB, BatchMigrateProgressReport.ATTRIBUTE_STATUS,
    BatchMigrateProgressReport.ATTRIBUTE_ERRORS})
public class BatchMigrateProgressReport {

    static final String ATTRIBUTE_BEFORE_JOB = "before_job";
    static final String ATTRIBUTE_AFTER_JOB = "after_job";
    static final String ATTRIBUTE_MIGRATED = "migrated";
    static final String ATTRIBUTE_STATUS = "status";
    static final String ATTRIBUTE_ERRORS = "errors";

    @JsonProperty(ATTRIBUTE_BEFORE_JOB)
    private MigrateProgressReport beforeJob;

    @JsonProperty(ATTRIBUTE_AFTER_JOB)
    private MigrateProgressReport afterJob;

    @JsonProperty(ATTRIBUTE_MIGRATED)
    private List<DocumentContentVersionModel> migratedDocumentContentVersions;

    @JsonProperty(ATTRIBUTE_STATUS)
    private HttpStatus status;

    @JsonInclude(NON_EMPTY)
    @JsonProperty(ATTRIBUTE_ERRORS)
    private List<String> errors;

    protected BatchMigrateProgressReport(MigrateProgressReport beforeJob,
                                         List<DocumentContentVersion> migratedDocumentContentVersions,
                                         MigrateProgressReport afterJob) {
        this.beforeJob = beforeJob;
        this.migratedDocumentContentVersions = migratedDocumentContentVersions.stream()
            .map(dcv -> new DocumentContentVersionModel(dcv))
            .collect(toList());
        this.afterJob = afterJob;
        this.status = OK;
    }
}
