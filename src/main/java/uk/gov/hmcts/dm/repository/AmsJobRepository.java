package uk.gov.hmcts.dm.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import uk.gov.hmcts.dm.domain.AmsJob;

@Repository
public interface AmsJobRepository extends JpaRepository<AmsJob, Long> {
}
