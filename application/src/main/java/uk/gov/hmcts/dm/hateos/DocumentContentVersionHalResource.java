package uk.gov.hmcts.dm.hateos;

import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

import java.util.Date;

import org.springframework.beans.BeanUtils;
import org.springframework.hateoas.core.Relation;

import lombok.Data;
import lombok.EqualsAndHashCode;
import uk.gov.hmcts.dm.controller.BlobStorageMigrationController;
import uk.gov.hmcts.dm.controller.DocumentContentVersionController;
import uk.gov.hmcts.dm.controller.DocumentThumbnailController;
import uk.gov.hmcts.dm.controller.StoredDocumentController;
import uk.gov.hmcts.dm.domain.DocumentContentVersion;

@Data
@EqualsAndHashCode(callSuper = true)
@Relation(collectionRelation = "documentVersions")
public class DocumentContentVersionHalResource extends HalResource {

    private Long size;

    private String mimeType;

    private String originalDocumentName;

    private String createdBy;

    private Date createdOn;

    public DocumentContentVersionHalResource(DocumentContentVersion documentContentVersion) {
        BeanUtils.copyProperties(documentContentVersion, this);

        add(linkTo(methodOn(StoredDocumentController.class)
            .getMetaData(documentContentVersion.getStoredDocument().getId())).withRel("document"));

        add(linkTo(methodOn(DocumentContentVersionController.class).getDocumentContentVersionDocument(
            documentContentVersion.getStoredDocument().getId(),
            documentContentVersion.getId())).withRel("self"));

        add(linkTo(methodOn(DocumentContentVersionController.class).getDocumentContentVersionDocumentBinary(
            documentContentVersion.getStoredDocument().getId(),
            documentContentVersion.getId(), null)).withRel("binary"));

        add(linkTo(methodOn(DocumentThumbnailController.class).getDocumentContentVersionDocumentPreviewThumbnail(
            documentContentVersion.getStoredDocument().getId(),
            documentContentVersion.getId())).withRel("thumbnail"));

        add(linkTo(methodOn(BlobStorageMigrationController.class).migrateDocument(
            documentContentVersion.getStoredDocument().getId(),
            documentContentVersion.getId())).withRel("migrate"));
    }

    public Date getCreatedOn() {
        return (createdOn == null) ? null : new Date(createdOn.getTime());
    }

    public void setCreatedOn(Date createdOn) {
        this.createdOn = (createdOn == null) ? null : new Date(createdOn.getTime());
    }

}
