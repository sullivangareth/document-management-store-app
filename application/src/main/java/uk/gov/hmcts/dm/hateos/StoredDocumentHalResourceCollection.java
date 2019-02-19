package uk.gov.hmcts.dm.hateos;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.hateoas.Resources;

import uk.gov.hmcts.dm.domain.StoredDocument;

public class StoredDocumentHalResourceCollection extends Resources<StoredDocumentHalResource> {

    public StoredDocumentHalResourceCollection(List<StoredDocument> storedDocuments) {
        super(storedDocuments
                .stream()
                .map(StoredDocumentHalResource::new)
                .collect(Collectors.toList()));

    }
}
