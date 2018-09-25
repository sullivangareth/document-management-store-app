package uk.gov.hmcts.dm.domain;

import lombok.Getter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;
import java.util.Date;
import java.util.UUID;

//Entityauditentry
@Entity
@Table(name="auditentry")
public class MigrateEntry {

//    type                      | character varying(31)       | not null
//    id                        | uuid                        | not null
//    action                    | character varying(255)      |
//    recordeddatetime          | timestamp without time zone |
//    username                  | character varying(255)      |
//    storeddocument_id         | uuid                        |
//    documentcontentversion_id | uuid                        |
//    servicename               | character varying(255)      |

    @Id
    @GeneratedValue(generator = "uuid2")
    @GenericGenerator(name = "uuid2", strategy = "uuid2")
    @Getter
    private UUID id;

    private String type;

    @NotNull
    @Enumerated(EnumType.STRING)
    private AuditActions action;

    @NotNull
    @Temporal(TemporalType.TIMESTAMP)
    private Date recordedDateTime;

    private UUID storeddocument_id;

    private UUID documentcontentversion_id;

    private String servicename;

    /**
     * Default constructor.
     */
    // used by jpa
    public MigrateEntry() {
        // Empty body intended
    }

    public MigrateEntry(String type,
                        AuditActions action,
                        DocumentContentVersion documentcontentversion,
                        String serviceName) {
        this.type = type;
        this.action = action;
        this.storeddocument_id = documentcontentversion.getStoredDocument().getId();
        this.documentcontentversion_id = documentcontentversion.getId();
        this.servicename = serviceName;
        this.recordedDateTime = new Date();
    }
}
