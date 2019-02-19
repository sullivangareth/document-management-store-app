package uk.gov.hmcts.dm.hateos;

import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

import java.util.Date;

import org.springframework.beans.BeanUtils;
import org.springframework.hateoas.core.Relation;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import uk.gov.hmcts.dm.controller.DocumentContentVersionController;
import uk.gov.hmcts.dm.controller.StoredDocumentController;
import uk.gov.hmcts.dm.domain.AuditActions;
import uk.gov.hmcts.dm.domain.DocumentContentVersionAuditEntry;
import uk.gov.hmcts.dm.domain.StoredDocumentAuditEntry;

@EqualsAndHashCode(callSuper = true)
@Relation(collectionRelation = "auditEntries")
public class StoredDocumentAuditEntryHalResource extends HalResource {

    @Getter
    @Setter
    private AuditActions action;

    @Getter
    @Setter
    private String username;

    private Date recordedDateTime;

    @Getter
    @Setter
    private String type;

    public StoredDocumentAuditEntryHalResource(StoredDocumentAuditEntry storedDocumentAuditEntry) {
        BeanUtils.copyProperties(storedDocumentAuditEntry, this);
        setType(storedDocumentAuditEntry.getClass().getSimpleName());
        add(linkTo(methodOn(StoredDocumentController.class).getMetaData(storedDocumentAuditEntry.getStoredDocument().getId())).withRel("document"));
        if (storedDocumentAuditEntry instanceof DocumentContentVersionAuditEntry) {
            DocumentContentVersionAuditEntry documentContentVersionAuditEntry = (DocumentContentVersionAuditEntry) storedDocumentAuditEntry;
            add(linkTo(methodOn(DocumentContentVersionController.class)
                    .getDocumentContentVersionDocument(
                            storedDocumentAuditEntry.getStoredDocument().getId(),
                            documentContentVersionAuditEntry.getDocumentContentVersion().getId())).withRel("documentContentVersion"));
        }
    }

    public Date getRecordedDateTime() {
        return (recordedDateTime == null) ? null : new Date(recordedDateTime.getTime());
    }

    public void getRecordedDateTime(Date recordedDateTime) {
        this.recordedDateTime = (recordedDateTime == null) ? null : new Date(recordedDateTime.getTime());
    }

}
