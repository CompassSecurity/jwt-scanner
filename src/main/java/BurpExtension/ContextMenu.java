/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package BurpExtension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.apache.commons.collections4.IterableUtils;

public class ContextMenu implements ContextMenuItemsProvider
{
    private final MontoyaApi api;
    private final Executor executor = Executors.newSingleThreadExecutor();

    private final JwtAuditIssueEquator jwtAuditIssueEquator = new JwtAuditIssueEquator();

    public ContextMenu(MontoyaApi api)
    {
        this.api = api;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        if (event.isFromTool(ToolType.PROXY, ToolType.REPEATER, ToolType.TARGET, ToolType.LOGGER, ToolType.INTRUDER))
        {
            List<Component> menuItemList = new ArrayList<>();

            HttpRequestResponse requestResponse;

            // determine if context menu is triggered on message editor
            boolean editorIsPresent = event.messageEditorRequestResponse().isPresent();
            if (editorIsPresent) {
                requestResponse =  event.messageEditorRequestResponse().get().requestResponse();
            } else {
                List<HttpRequestResponse> selectedRequests = event.selectedRequestResponses();

                // only 1 request is support at this time, otherwise no menu item is shown
                if (selectedRequests.size() == 1) {
                    requestResponse = selectedRequests.get(0);
                } else {
                    return null;
                }
            }

            JwtScanCheck scan = new JwtScanCheck(api);
            JwtInsertionPointProvider insertionPointProvider = new JwtInsertionPointProvider(api);

            // Autodetect JWT
            JMenuItem autodetectMenuItem = new JMenuItem("Autodetect JWT");
            autodetectMenuItem.addActionListener(l -> SwingUtilities.invokeLater(() ->
                    this.executor.execute(() -> {
                                List<AuditInsertionPoint> auditInsertionPoints = insertionPointProvider.provideInsertionPoints(requestResponse);

                                for (AuditInsertionPoint insertionPoint : auditInsertionPoints) {
                                    AuditResult auditResult = scan.activeAudit(requestResponse,insertionPoint,true);

                                    for (AuditIssue issue : auditResult.auditIssues()) {
                                        if (!IterableUtils.contains(api.siteMap().issues(), issue, jwtAuditIssueEquator)) {
                                            api.siteMap().add(issue);
                                        }
                                    }
                                }
                    }))
            );
            menuItemList.add(autodetectMenuItem);

            // Selected JWT
            if (editorIsPresent && event.messageEditorRequestResponse().get().selectionOffsets().isPresent()) {

                int startindex = event.messageEditorRequestResponse().get().selectionOffsets().get().startIndexInclusive();
                int endindex = event.messageEditorRequestResponse().get().selectionOffsets().get().endIndexExclusive();

                List<AuditInsertionPoint> auditInsertionPoints = insertionPointProvider.provideInsertionPointsInSelection(requestResponse, startindex, endindex);

                if (!auditInsertionPoints.isEmpty()) {
                    JMenuItem retrieveSelectedRequestItem = new JMenuItem("Selected JWT");
                    retrieveSelectedRequestItem.addActionListener(l -> SwingUtilities.invokeLater(() ->
                            this.executor.execute(() -> {
                                for (AuditInsertionPoint insertionPoint : auditInsertionPoints) {
                                    AuditResult auditResult = scan.activeAudit(requestResponse,insertionPoint,true);

                                    for (AuditIssue issue : auditResult.auditIssues()) {
                                        if (!IterableUtils.contains(api.siteMap().issues(), issue, jwtAuditIssueEquator)) {
                                            api.siteMap().add(issue);
                                        }
                                    }
                                }
                            }))
                    );

                    menuItemList.add(retrieveSelectedRequestItem);
                }
            }

            return menuItemList;
        }

        return null;
    }
}
