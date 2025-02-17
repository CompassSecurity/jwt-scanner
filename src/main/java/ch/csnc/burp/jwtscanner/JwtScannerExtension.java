package ch.csnc.burp.jwtscanner;

import burp.api.montoya.MontoyaApi;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import static java.util.Objects.requireNonNull;

// TODO test on community edition
public class JwtScannerExtension implements burp.api.montoya.BurpExtension {

    private static MontoyaApi api;
    private static MontoyaApiAdapter apiAdapter = new MontoyaApiAdapter();

    public static MontoyaApi api() {
        return api;
    }

    public static MontoyaApiAdapter apiAdapter() {
        return apiAdapter;
    }

    @Override
    public void initialize(MontoyaApi api) {
        JwtScannerExtension.api = api;
        JwtScannerExtension.apiAdapter = new MontoyaApiAdapter(api);

        api.extension().setName("JWT Scanner");
        api.userInterface().registerContextMenuItemsProvider(new ContextMenu());
        api.scanner().registerInsertionPointProvider(new JwtInsertionPointProvider());
        api.scanner().registerScanCheck(new JwtScanCheck());

        var versionTxt = "/version.txt";
        try (var stream = getClass().getResourceAsStream(versionTxt)) {
            var reader = new BufferedReader(new InputStreamReader(requireNonNull(stream, versionTxt)));
            reader.lines().forEach(api.logging()::logToOutput);
        } catch (Exception exc) {
            api.logging().logToError("Could not read %s".formatted(versionTxt));
            api.logging().logToError(exc);
        }
    }
}