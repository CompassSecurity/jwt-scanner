/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package BurpExtension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.HttpRequestEditor;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class ContextMenu implements ContextMenuItemsProvider
{

    private final MontoyaApi api;
    private Scanner scanner;
    private final Executor executor = Executors.newSingleThreadExecutor();

    public ContextMenu(MontoyaApi api)
    {

        this.api = api;
        scanner = api.scanner();
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        if (event.isFromTool(ToolType.PROXY, ToolType.REPEATER, ToolType.TARGET, ToolType.LOGGER, ToolType.INTRUDER))
        {
            List<Component> menuItemList = new ArrayList<>();

            JMenuItem retrieveRequestItem = new JMenuItem("Autodetect JWT");

            HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0);

            JWTScanCheck scan = new JWTScanCheck(api);
            JwtInsertionPoint insertionPoint = new JwtInsertionPoint(api,requestResponse.request());
            retrieveRequestItem.addActionListener(l -> SwingUtilities.invokeLater(() ->
                this.executor.execute(() -> scan.activeAudit(requestResponse,insertionPoint)))
            );
            menuItemList.add(retrieveRequestItem);

            if (event.messageEditorRequestResponse().get().selectionOffsets().isPresent()) {
                JMenuItem retrieveSelectedRequestItem = new JMenuItem("Selected JWT");
                int startindex = event.messageEditorRequestResponse().get().selectionOffsets().get().startIndexInclusive();
                int endindex = event.messageEditorRequestResponse().get().selectionOffsets().get().endIndexExclusive();
                JWTScanCheck scanSelected = new JWTScanCheck(api);
                JwtInsertionPoint insertionPointSelected = new JwtInsertionPoint(api,requestResponse.request(),startindex,endindex);
                retrieveSelectedRequestItem.addActionListener(l -> SwingUtilities.invokeLater(() ->
                        this.executor.execute(() -> scanSelected.activeAudit(requestResponse,insertionPointSelected)))
                );
                menuItemList.add(retrieveSelectedRequestItem);

            }

            return menuItemList;
        }

        return null;
    }
}
