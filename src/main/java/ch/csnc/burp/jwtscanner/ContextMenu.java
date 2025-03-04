package ch.csnc.burp.jwtscanner;

import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import ch.csnc.burp.jwtscanner.checks.Checks;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * This class provides the ability to run {@link JwtScanCheck JwtScanChecks} explicitly,
 * without the need to initiate a full active scan. As of the time of writing, the
 * {@link burp.api.montoya.MontoyaApi MontoyaApi} does not allow for the independent
 * execution of a registered {@link burp.api.montoya.scanner.ScanCheck ScanCheck}.
 * Consequently, some logic that is typically managed by Burp Suite is reimplemented here,
 * such as adding {@link AuditIssue AuditIssues} to the
 * {@link burp.api.montoya.sitemap.SiteMap SiteMap}.
 */
public class ContextMenu implements burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider {

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent menuEvent) {
        var menuItems = new ArrayList<Component>();

        var siteMap = JwtScannerExtension.api().siteMap();

        if (menuEvent.selectedRequestResponses().size() == 2) {
            var request1 = menuEvent.selectedRequestResponses().get(0).request();
            var request2 = menuEvent.selectedRequestResponses().get(1).request();
            var request1MatchResults = Jwt.PATTERN.matcher(request1.toString()).results().toList();
            var request2MatchResults = Jwt.PATTERN.matcher(request2.toString()).results().toList();

            if (request1MatchResults.size() == 1 && request2MatchResults.size() == 1) {
                var jwt1 = new Jwt(request1MatchResults.getFirst().group());
                var jwt2 = new Jwt(request2MatchResults.getFirst().group());
                var forgePublicKeyMenuItem = new JMenuItem("Forge public key");
                forgePublicKeyMenuItem.addActionListener(actionEvent -> {
                    JwtScannerExtension.logging().raiseInfoEvent("started forging public keys.");
                    Sign2n.forgePublicKeys(jwt1, jwt2)
                            .thenAccept(publicKeys -> {
                                JwtScannerExtension.storage().putForgedPublicKeys(publicKeys);
                                if (!publicKeys.isEmpty()) {
                                    JwtScannerExtension.storage().putForgedPublicKeys(publicKeys);
                                    siteMap.add(JwtAuditIssues.forgedPublicKeys(menuEvent.selectedRequestResponses().getFirst(), jwt1, jwt2, publicKeys));
                                    JwtScannerExtension.logging().raiseInfoEvent("forging public keys was successful.");
                                } else {
                                    JwtScannerExtension.logging().raiseInfoEvent("no public keys could be forged.");
                                }
                            })
                            .orTimeout(5, TimeUnit.MINUTES)
                            .exceptionally(exc -> {
                                JwtScannerExtension.logging().raiseErrorEvent("forging public keys failed.");
                                JwtScannerExtension.logging().logToError(exc);
                                return null;
                            });
                });
                menuItems.add(forgePublicKeyMenuItem);
            }
        }

        menuEvent.messageEditorRequestResponse()
                .flatMap(MessageEditorHttpRequestResponse::selectionOffsets)
                .ifPresent(selectionOffsets -> {
                    var scanSelectedMenuItem = new JMenuItem("Scan selected");
                    scanSelectedMenuItem.addActionListener(actionEvent -> {
                        executor.execute(() -> {
                            var requestResponse = menuEvent.messageEditorRequestResponse()
                                    .map(MessageEditorHttpRequestResponse::requestResponse)
                                    .orElseThrow();
                            var auditInsertionPoint = AuditInsertionPoint.auditInsertionPoint(
                                    "JWT detected",
                                    requestResponse.request(),
                                    selectionOffsets.startIndexInclusive(),
                                    selectionOffsets.endIndexExclusive());
                            Checks.performAll(requestResponse, auditInsertionPoint, siteMap::add);
                        });
                    });
                    menuItems.add(scanSelectedMenuItem);
                });

        var scanAutodetectMenuItem = new JMenuItem("Scan (autodetect)");
        scanAutodetectMenuItem.addActionListener(actionEvent -> {
            executor.execute(() -> {
                var insertionPointProvider = new JwtInsertionPointProvider();
                var requestResponses = menuEvent.messageEditorRequestResponse()
                        .map(MessageEditorHttpRequestResponse::requestResponse)
                        .map(List::of)
                        .orElseGet(menuEvent::selectedRequestResponses);
                for (var requestResponse : requestResponses) {
                    var auditInsertionPoints = insertionPointProvider.provideInsertionPoints(requestResponse);
                    for (var auditInsertionPoint : auditInsertionPoints) {
                        Checks.performAll(requestResponse, auditInsertionPoint, siteMap::add);
                    }
                }
            });
        });
        menuItems.add(scanAutodetectMenuItem);

        return menuItems;
    }


}
