package BurpExtension;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import org.apache.commons.collections4.Equator;
import org.apache.commons.collections4.functors.DefaultEquator;

public class JwtAuditIssueEquator implements Equator<AuditIssue> {

    @Override
    public boolean equate(AuditIssue auditIssue, AuditIssue t1) {
        // name of issue needs to match
        if (auditIssue.name().equals(t1.name())) {
            // HTTP Service needs to match
            if (auditIssue.httpService().equals(t1.httpService())) {
                // path needs to match
                if (auditIssue.requestResponses().get(0).request().path().equals(t1.requestResponses().get(0).request().path())) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public int hash(AuditIssue auditIssue) {
        return DefaultEquator.INSTANCE.hash(auditIssue);
    }
}
