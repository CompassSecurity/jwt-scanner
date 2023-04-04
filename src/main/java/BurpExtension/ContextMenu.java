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
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import io.jsonwebtoken.*;

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
        if (event.isFromTool(ToolType.PROXY, ToolType.REPEATER, ToolType.TARGET, ToolType.LOGGER))
        {
            List<Component> menuItemList = new ArrayList<>();

            JMenuItem retrieveRequestItem = new JMenuItem("Attack JWT");

            HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0);

            for (int i=0; i <= requestResponse.request().headers().toArray().length; i++){
                if (requestResponse.request().headers().get(i).name().equals("Authorization")){
                    String jwt = requestResponse.request().headers().get(i).value().toString();
                    if (jwt.startsWith("Bearer ")){
                        jwt = jwt.substring("Bearer ".length());
                    }
                    api.logging().logToOutput(jwt);
                    // Validate if the jwt  is already expired somehow burp returns class not found: io.jseonwebtokens.Jwts
                    // if (isJwtExpired(jwt)) {
                    //     api.logging().logToOutput("using JWT: " + jwt);
                    // } else {
                    //     api.logging().raiseErrorEvent("JWT expired, please choose a valid one!");
                    // }
                    break;
                }
            }
            JWTScanCheck scan = new JWTScanCheck(api);
            JwtInsertionPoint insertionPoint = new JwtInsertionPoint(api,requestResponse.request());
            retrieveRequestItem.addActionListener(l -> SwingUtilities.invokeLater(() ->
                this.executor.execute(() -> scan.activeAudit(requestResponse,insertionPoint)))
            );
            menuItemList.add(retrieveRequestItem);

            return menuItemList;
        }

        return null;
    }

    private static boolean isJwtExpired(String jwt) {
        // Parse the JWT
        Jwt<Header, Claims> parsedJwt = Jwts.parserBuilder().build().parseClaimsJwt(jwt);
        Claims claims = parsedJwt.getBody();

        long expirationTime = claims.getExpiration().getTime();

        long currentTime = System.currentTimeMillis();
        return currentTime >= expirationTime;
    }
}
