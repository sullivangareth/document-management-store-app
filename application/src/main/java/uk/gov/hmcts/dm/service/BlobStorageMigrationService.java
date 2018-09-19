package uk.gov.hmcts.dm.service;

import com.microsoft.azure.storage.StorageException;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.blob.CloudBlockBlob;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.token.Sha512DigestUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uk.gov.hmcts.dm.domain.DocumentContentVersion;
import uk.gov.hmcts.dm.exception.CantReadDocumentContentVersionBinaryException;
import uk.gov.hmcts.dm.exception.DocumentContentVersionNotFoundException;
import uk.gov.hmcts.dm.exception.DocumentNotFoundException;
import uk.gov.hmcts.dm.exception.FileStorageException;
import uk.gov.hmcts.dm.exception.ValidationErrorException;
import uk.gov.hmcts.dm.repository.DocumentContentVersionRepository;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.net.URISyntaxException;
import java.sql.Blob;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.springframework.data.domain.Sort.Direction.DESC;
import static uk.gov.hmcts.dm.domain.AuditActions.MIGRATED;

@Service
@Transactional
public class BlobStorageMigrationService {

    private final CloudBlobContainer cloudBlobContainer;
    private final AuditEntryService auditEntryService;
    private final StoredDocumentService storedDocumentService;
    private final DocumentContentVersionRepository documentContentVersionRepository;
    private MigrationAuthToken migrationAuthToken;

    @Value("${blobstore.migrate.token.size:31}")
    private int numerOfRandomCharacters;
    @Value("${blobstore.migrate.token.ttlInSeconds:59}")
    private int ttlInSeconds;
    @Value("${blobstore.migrate.default.batchSize:5}")
    private int defaultBatchSize;
    @Value("${blobstore.migrate.ccd.secret:y2hahvdZ9evcTVq2}")
    private String migrateSecret;

    @Autowired
    public BlobStorageMigrationService(CloudBlobContainer cloudBlobContainer,
                                       AuditEntryService auditEntryService,
                                       DocumentContentVersionRepository documentContentVersionRepository,
                                       StoredDocumentService storedDocumentService) {
        this.cloudBlobContainer = cloudBlobContainer;
        this.auditEntryService = auditEntryService;
        this.documentContentVersionRepository = documentContentVersionRepository;
        this.storedDocumentService = storedDocumentService;
        this.migrationAuthToken = newMigrationAuthToken();
    }

    public void migrateDocumentContentVersion(@NotNull UUID documentId, @NotNull UUID versionId) {

        final DocumentContentVersion documentContentVersion = getDocumentContentVersion(documentId, versionId);
        migrateDocumentContentVersion(documentContentVersion);
    }

    private void migrateDocumentContentVersion(DocumentContentVersion documentContentVersion) {
        if (isBlank(documentContentVersion.getContentChecksum())) {
            uploadBinaryStream(documentContentVersion);
            // we cannot use documentContentVersionRepository.save
            // because { @link ByteWrappingBlobType#replace} is not implemented
            documentContentVersionRepository.update(documentContentVersion.getId(),
                                                    documentContentVersion.getContentUri());
            auditEntryService.createAndSaveEntry(documentContentVersion, MIGRATED);
        }
    }

        public MigrateProgressReport getMigrateProgressReport() {
        return new MigrateProgressReport(documentContentVersionRepository.countByContentChecksumIsNull(),
                                         documentContentVersionRepository.countByContentChecksumIsNotNull());
    }

    public BatchMigrateProgressReport batchMigrate(int limit, boolean mockRun) {
        MigrateProgressReport before = getMigrateProgressReport();

        final List<DocumentContentVersion> dcvList = documentContentVersionRepository
            .findByContentChecksumIsNullAndDocumentContentIsNotNull(
            new PageRequest(0, limit, DESC, "createdOn"));

        if (!mockRun) {
            dcvList.forEach(dcv -> migrateDocumentContentVersion(dcv));
        }

        MigrateProgressReport after = getMigrateProgressReport();
        newMigrationAuthToken();
        return new BatchMigrateProgressReport(before, dcvList, after);
    }

    public BatchMigrateProgressReport batchMigrate(final String migrateSecret,
                                                   final String authToken,
                                                   final Integer limit,
                                                   final Boolean mockRun) {
        if (!this.migrationAuthToken.isValid(migrateSecret, authToken)) {
            throw new ValidationErrorException("Bad authToken");
        }
        return batchMigrate(defaultIfNull(limit, defaultBatchSize), defaultIfNull(mockRun, false));
    }

    public String getAuthToken() {
        this.migrationAuthToken = newMigrationAuthToken();
        return this.migrationAuthToken.getToken();
    }

    private DocumentContentVersion getDocumentContentVersion(final @NotNull UUID documentId,
                                                             final @NotNull UUID versionId) {
        // Sonar fails us if we use orElseThrow
        if (!storedDocumentService.findOneWithBinaryData(documentId).isPresent()) {
            throw new DocumentNotFoundException(documentId);
        }

        return Optional
            .ofNullable(documentContentVersionRepository.findOne(versionId))
            .orElseThrow(() -> new DocumentContentVersionNotFoundException(versionId));
    }

    private MigrationAuthToken newMigrationAuthToken() {
        return new MigrationAuthToken(migrateSecret, numerOfRandomCharacters, ttlInSeconds);
    }

    private void uploadBinaryStream(DocumentContentVersion dcv) {
        try {
            CloudBlockBlob cloudBlockBlob = getCloudFile(dcv.getId());
            Blob data = dcv.getDocumentContent().getData();
            cloudBlockBlob.upload(data.getBinaryStream(), dcv.getSize());
            dcv.setContentUri(cloudBlockBlob.getUri().toString());
            dcv.setContentChecksum(Sha512DigestUtils.shaHex(data.getBytes(1, (int)data.length())));
        } catch (URISyntaxException | StorageException | IOException e) {
            throw new FileStorageException(e, dcv.getStoredDocument().getId(), dcv.getId());
        } catch (SQLException e) {
            throw new CantReadDocumentContentVersionBinaryException(e, dcv);
        }
    }

    private CloudBlockBlob getCloudFile(UUID uuid) throws StorageException, URISyntaxException {
        return cloudBlobContainer.getBlockBlobReference(uuid.toString());
    }
}
