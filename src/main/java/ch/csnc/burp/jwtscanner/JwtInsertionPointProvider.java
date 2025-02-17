package ch.csnc.burp.jwtscanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;

import java.util.ArrayList;
import java.util.List;

public class JwtInsertionPointProvider implements AuditInsertionPointProvider {

    @Override
    public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse httpRequestResponse) {
        var auditInsertionPoints = new ArrayList<AuditInsertionPoint>();
        var requestAsString = httpRequestResponse.request().toString();
        var matcher = Jwt.PATTERN.matcher(requestAsString);
        while (matcher.find()) {
            auditInsertionPoints.add(
                    AuditInsertionPoint.auditInsertionPoint(
                            "Detected JWT",
                            httpRequestResponse.request(),
                            matcher.start(),
                            matcher.end()));
        }
        return auditInsertionPoints;
    }

}
