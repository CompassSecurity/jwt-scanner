package BurpExtension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

//Burp will auto-detect and load any class that extends BurpExtension.
public class BurpExtender implements BurpExtension
{
    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName("JWT-scanner");
        api.userInterface().registerContextMenuItemsProvider(new ContextMenu(api));
        api.scanner().registerScanCheck(new JwtScanCheck(api));
        api.scanner().registerInsertionPointProvider(new JwtInsertionPointProvider(api));
    }
}