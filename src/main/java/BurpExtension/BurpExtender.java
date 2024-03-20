package BurpExtension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

//Burp will auto-detect and load any class that extends BurpExtension.
public class BurpExtender implements BurpExtension
{
    @Override
    public void initialize(MontoyaApi api)
    {
        // set extension name
        api.extension().setName("JWT-scanner");
        api.userInterface().registerContextMenuItemsProvider(new ContextMenu(api));

        Logging logging = api.logging();
        logging.raiseInfoEvent("JWT-scanner loaded.");

        api.scanner().registerScanCheck(new JWTScanCheck(api));

    }
}