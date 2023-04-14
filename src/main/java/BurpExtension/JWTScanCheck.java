package BurpExtension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;

class JWTScanCheck implements ScanCheck
{
    private final MontoyaApi api;

    JWTScanCheck(MontoyaApi api)
    {
        this.api = api;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint)
    {
        JwtModifier jwtModifier = new JwtModifier(api);
        String origJwt = "";
        String regex = "(ey[a-zA-Z0-9_=]+)\\.(ey[a-zA-Z0-9_=]+)\\.([a-zA-Z0-9_\\-\\+\\/=]*)";
        Pattern pattern = Pattern.compile(regex);
        HttpRequest req = baseRequestResponse.request();
        Matcher matcher = pattern.matcher(req.toString());

        if (matcher.find()) {
            int startIndex = matcher.start();
            int endIndex = matcher.end();
            origJwt = req.toString().substring(startIndex,endIndex);
            api.logging().logToOutput("orig: " + origJwt);
            // Validate if the origJwt is still valid
            if (jwtModifier.isJwtNotExpired(origJwt)) {
                api.logging().logToOutput("using JWT:\n" + origJwt);
                api.logging().logToOutput("self sig :\n" + jwtModifier.wrongSignature(origJwt));
                api.logging().logToOutput("Empty sig: \n" + jwtModifier.emptyPassword(origJwt));
                api.logging().logToOutput("invalid ECDSA: \n" + jwtModifier.invalidEcdsa(origJwt));
                api.logging().logToOutput("JWKS injecition: \n" + jwtModifier.JwksInjection(origJwt));
            } else {
                api.logging().raiseErrorEvent("JWT expired, please choose a valid one!");
                api.logging().logToOutput("JWT expired, please choose a valid one!");
            }

        } else {
            api.logging().logToError("No JWT found.");
        }




        /* collaborator test
        Collaborator collaborator = api.collaborator();
        CollaboratorClient collaboratorClient = collaborator.createClient();

        CollaboratorPayload payload = collaboratorClient.generatePayload();
        String payloadString = payload.toString();
        api.logging().logToOutput("payloadstrin: " + payloadString);
        */


        HttpRequest checkRequest = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.JwksInjection(origJwt)));
        HttpRequestResponse checkRequestResponse = api.http().sendRequest(checkRequest);
        if (checkRequestResponse.response().statusCode() == 200){
            api.siteMap().add(JwtAuditIssues.getAlgNone(baseRequestResponse.request().url(), checkRequestResponse));
        }

        /* Collaborator check
        for (Interaction interaction : collaboratorClient.getAllInteractions()){
            api.logging().logToOutput("Interaction id: " + interaction.id());
        }*/

        return null;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse)
    {
        return null;
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue)
    {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }
}
