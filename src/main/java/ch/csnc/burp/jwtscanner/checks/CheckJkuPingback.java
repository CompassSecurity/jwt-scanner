package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;
import ch.csnc.burp.jwtscanner.JwtScannerExtension;

import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class CheckJkuPingback extends Check {

    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    @Override
    public Optional<AuditIssue> perform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var collaborator = JwtScannerExtension.api().collaborator().createClient();
        var jwt = Jwt.newBuilder(auditInsertionPoint.baseValue()).withHeader("jku", collaborator.generatePayload()).build();
        var checkRequest = auditInsertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(jwt.encode())).withService(baseRequestResponse.httpService());
        var checkRequestResponse = JwtScannerExtension.api().http().sendRequest(checkRequest);
        executor.schedule(() -> {
            if (!collaborator.getAllInteractions().isEmpty()) {
                JwtScannerExtension.api().siteMap().add(JwtAuditIssues.jkuPingback(jwt, AuditIssueConfidence.FIRM, baseRequestResponse, checkRequestResponse));
            }
        }, 30, TimeUnit.SECONDS);
        return Optional.empty();
    }

}
