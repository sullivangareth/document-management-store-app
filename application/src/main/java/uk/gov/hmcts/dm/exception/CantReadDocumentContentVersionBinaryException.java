package uk.gov.hmcts.dm.exception;

import lombok.Getter;
import uk.gov.hmcts.dm.domain.DocumentContentVersion;

/**
 * Created by pawel on 10/08/2017.
 */
public class CantReadDocumentContentVersionBinaryException extends RuntimeException {

    @Getter
    private final transient DocumentContentVersion documentContentVersion;

    public CantReadDocumentContentVersionBinaryException(String message, DocumentContentVersion documentContentVersion) {
        super(message);
        this.documentContentVersion = documentContentVersion;
    }

    public CantReadDocumentContentVersionBinaryException(Throwable cause, DocumentContentVersion documentContentVersion) {
        super(cause);
        this.documentContentVersion = documentContentVersion;
    }
}
