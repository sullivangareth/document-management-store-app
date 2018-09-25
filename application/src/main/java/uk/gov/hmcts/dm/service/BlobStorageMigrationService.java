package uk.gov.hmcts.dm.service;

import com.microsoft.azure.storage.StorageException;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.blob.CloudBlockBlob;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.token.Sha512DigestUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uk.gov.hmcts.dm.domain.DocumentContentVersion;
import uk.gov.hmcts.dm.domain.MigrateEntry;
import uk.gov.hmcts.dm.exception.CantReadDocumentContentVersionBinaryException;
import uk.gov.hmcts.dm.exception.DocumentContentVersionNotFoundException;
import uk.gov.hmcts.dm.exception.DocumentNotFoundException;
import uk.gov.hmcts.dm.exception.FileStorageException;
import uk.gov.hmcts.dm.exception.ValidationErrorException;
import uk.gov.hmcts.dm.repository.DocumentContentVersionRepository;
import uk.gov.hmcts.dm.repository.MigrateEntryRepository;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.validation.constraints.NotNull;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.sql.Blob;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.apache.commons.codec.binary.Base64.encodeBase64;
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.springframework.data.domain.Sort.Direction.DESC;
import static uk.gov.hmcts.dm.domain.AuditActions.MIGRATED;

@Service
@Transactional
@Slf4j
public class BlobStorageMigrationService {

    public static final String SSH_ALGORITHM = "RSA";
    private final CloudBlobContainer cloudBlobContainer;
    private final StoredDocumentService storedDocumentService;
    private final DocumentContentVersionRepository documentContentVersionRepository;
    private final MigrateEntryRepository auditEntryRepository;
    private final RsaPublicKeyReader sshPublicKeyParser;

    private MigrationAuthToken migrationAuthToken;
    private RSAPublicKeySpec rsaPublicKey;

    @Value("${blobstore.migrate.token.size:31}")
    private int numerOfRandomCharacters;
    @Value("${blobstore.migrate.token.ttlInSeconds:59}")
    private int ttlInSeconds;
    @Value("${bloYourbstore.migrate.default.batchSize:5}")
    private int defaultBatchSize;
    @Value("${blobstore.migrate.ccd.secret:y2hahvdZ9evcTVq2}")
    private String migrateSecret;
    @Value("${blobstore.migrate.ccd.publicKey}")
    private String migrationPublicKeyStringValue;

    @Autowired
    public BlobStorageMigrationService(CloudBlobContainer cloudBlobContainer,
                                       DocumentContentVersionRepository documentContentVersionRepository,
                                       StoredDocumentService storedDocumentService,
                                       MigrateEntryRepository auditEntryRepository,
                                       final RsaPublicKeyReader sshPublicKeyParser) {
        this.cloudBlobContainer = cloudBlobContainer;
        this.documentContentVersionRepository = documentContentVersionRepository;
        this.storedDocumentService = storedDocumentService;
        this.migrationAuthToken = newMigrationAuthToken();
        this.auditEntryRepository = auditEntryRepository;
        this.sshPublicKeyParser = sshPublicKeyParser;
        rsaPublicKey = sshPublicKeyParser.parsePublicKey(getMigrationPublicKeyStringValue());
    }

    public void migrateDocumentContentVersion(@NotNull UUID documentId, @NotNull UUID versionId) {

        final DocumentContentVersion documentContentVersion = getDocumentContentVersion(documentId, versionId);
        migrateDocumentContentVersion(documentContentVersion);
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

    public synchronized BatchMigrateProgressReport batchMigrate(final String migrateSecret,
                                                                final String authToken,
                                                                final Integer limit,
                                                                final Boolean mockRun) {
        if (!this.migrationAuthToken.isValid(migrateSecret, authToken)) {
            throw new ValidationErrorException("Bad authToken");
        }
        return batchMigrate(defaultIfNull(limit, defaultBatchSize), defaultIfNull(mockRun, false));
    }

    public String getAuthToken(String migrateSecret) {
        migrationAuthToken = newMigrationAuthToken();
        try {
            Cipher cipher = Cipher.getInstance(SSH_ALGORITHM);
            cipher.init(ENCRYPT_MODE, KeyFactory.getInstance(SSH_ALGORITHM).generatePublic(rsaPublicKey));
            return new String(encodeBase64(cipher.doFinal(migrationAuthToken.getToken().getBytes())));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
            IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException e) {
            throw new ValidationErrorException(e);
        }
    }

    private void migrateDocumentContentVersion(DocumentContentVersion documentContentVersion) {
        if (isBlank(documentContentVersion.getContentChecksum())) {
            log.info("Migrate DocumentContentVersion {}", documentContentVersion.getId());
            uploadBinaryStream(documentContentVersion);
            // we cannot use documentContentVersionRepository.save
            // because { @link ByteWrappingBlobType#replace} is not implemented
            documentContentVersionRepository.update(documentContentVersion.getId(),
                                                    documentContentVersion.getContentUri(),
                                                    documentContentVersion.getContentChecksum());
            auditEntryRepository.saveAndFlush(newAuditEntry(documentContentVersion, "TODO: Does Not Matter"));
        }
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
            final byte[] bytes = IOUtils.toByteArray(data.getBinaryStream());
            cloudBlockBlob.upload(new ByteArrayInputStream(bytes), dcv.getSize());
            dcv.setContentUri(cloudBlockBlob.getUri().toString());
            dcv.setContentChecksum(Sha512DigestUtils.shaHex(bytes));
            log.debug("Uploaded data to {} Size = {} checksum = {}", cloudBlockBlob.getUri(), dcv.getSize(), dcv
                .getContentChecksum());
        } catch (URISyntaxException | StorageException | IOException e) {
            throw new FileStorageException(e, dcv.getStoredDocument().getId(), dcv.getId());
        } catch (SQLException e) {
            log.error("Exception with Document Content Version {}", dcv.getId(), e);
            throw new CantReadDocumentContentVersionBinaryException(e, dcv);
        }
    }

    private CloudBlockBlob getCloudFile(UUID uuid) throws StorageException, URISyntaxException {
        return cloudBlobContainer.getBlockBlobReference(uuid.toString());
    }

    private MigrateEntry newAuditEntry(DocumentContentVersion documentContentVersion,
                                       String username) {
        MigrateEntry auditEntry = new MigrateEntry("Migrate content", MIGRATED,
                                                                         documentContentVersion,
                                                                         "Batch Migration Service");
        return auditEntry;
    }

    private String getMigrationPublicKeyStringValue() {
        return this.migrationPublicKeyStringValue;
    }

}
