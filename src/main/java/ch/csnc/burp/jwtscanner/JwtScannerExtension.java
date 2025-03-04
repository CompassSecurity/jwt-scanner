package ch.csnc.burp.jwtscanner;

import burp.api.montoya.MontoyaApi;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import static java.util.Objects.requireNonNull;

// TODO test on community edition
public class JwtScannerExtension implements burp.api.montoya.BurpExtension {

    private static MontoyaApi api;
    private static Logging logging;
    private static Storage storage;

    public static MontoyaApi api() {
        return api;
    }

    public static Logging logging() {
        return logging;
    }

    public static Storage storage() {
        return storage;
    }

    @Override
    public void initialize(MontoyaApi api) {
        JwtScannerExtension.api = api;
        JwtScannerExtension.logging = new Logging(api);
        JwtScannerExtension.storage = new Storage();

        api.extension().setName("JWT Scanner");
        api.userInterface().registerContextMenuItemsProvider(new ContextMenu());
        api.scanner().registerInsertionPointProvider(new JwtInsertionPointProvider());
        api.scanner().registerScanCheck(new JwtScanCheck());

        var versionTxt = "/version.txt";
        try (var stream = getClass().getResourceAsStream(versionTxt)) {
            var reader = new BufferedReader(new InputStreamReader(requireNonNull(stream, versionTxt)));
            reader.lines().forEach(JwtScannerExtension.logging()::logToOutput);
        } catch (Exception exc) {
            JwtScannerExtension.logging().logToError("Could not read %s".formatted(versionTxt));
            JwtScannerExtension.logging().logToError(exc);
        }
    }
}