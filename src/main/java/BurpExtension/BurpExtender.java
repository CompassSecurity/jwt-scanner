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
        api.extension().setName("JWT-attacker");
        api.userInterface().registerContextMenuItemsProvider(new ContextMenu(api));

        Logging logging = api.logging();

        // write a message to our output stream
        logging.logToOutput("Hello output.");

        // write a message to our error stream
        //logging.logToError("Hello error.");

        // write a message to the Burp alerts tab
        //logging.raiseInfoEvent("Hello info event.");
        logging.raiseDebugEvent("JWT-attaker loaded.");
        //logging.raiseErrorEvent("Hello error event.");
        //logging.raiseCriticalEvent("Hello critical event.");

        // throw an exception that will appear in our error stream
        // throw new RuntimeException("Hello exception.");
        api.scanner().registerScanCheck(new JWTScanCheck(api));

    }
}