package uk.gov.hmcts.dm.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;

import uk.gov.hmcts.dm.domain.StoredDocument;
import uk.gov.hmcts.dm.domain.StoredDocumentAuditEntry;

@Repository
public interface StoredDocumentAuditEntryRepository extends PagingAndSortingRepository<StoredDocumentAuditEntry, UUID> {

    List<StoredDocumentAuditEntry> findByStoredDocumentOrderByRecordedDateTimeAsc(StoredDocument storedDocument);

}
