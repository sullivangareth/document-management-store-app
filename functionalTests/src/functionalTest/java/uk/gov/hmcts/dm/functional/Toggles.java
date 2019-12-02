package uk.gov.hmcts.dm.functional;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "toggle")
public class Toggles {

    private boolean metadatasearchendpoint;
    private boolean documentandmetadatauploadendpoint;
    private boolean folderendpoint;
    private boolean includeidamhealth;
    private boolean ttl;

    public boolean isMetadatasearchendpoint() {
        return metadatasearchendpoint;
    }

    public boolean isDocumentandmetadatauploadendpoint() {
        return documentandmetadatauploadendpoint;
    }

    public boolean isFolderendpoint() {
        return folderendpoint;
    }

    public boolean isIncludeidamhealth() {
        return includeidamhealth;
    }

    public boolean isTtl() {
        return ttl;
    }
}
