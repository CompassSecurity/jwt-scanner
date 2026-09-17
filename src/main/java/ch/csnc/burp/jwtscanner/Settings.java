package ch.csnc.burp.jwtscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;

import static burp.api.montoya.ui.settings.SettingsPanelBuilder.settingsPanel;
import static burp.api.montoya.ui.settings.SettingsPanelPersistence.USER_SETTINGS;

/**
 * Exposes JWT Scanner's configuration in Burp's Settings dialog, backed by user-scoped persistence.
 */
public class Settings {

    private static final String SIMILARITY_THRESHOLD_SETTING = "similarity_threshold";
    private static final String DEFAULT_SIMILARITY_THRESHOLD = "0.8";

    private SettingsPanelWithData panel;

    public void register(MontoyaApi api) {
        this.panel = settingsPanel()
                .withTitle("JWT Scanner")
                .withDescription("Configure JWT Scanner behavior.")
                .withKeywords("jwt", "similarity", "threshold", "cosine")
                .withPersistence(USER_SETTINGS)
                .withSetting(SettingsPanelSetting.stringSetting(
                        "Cosine similarity threshold (0.0-1.0) above which a check response is considered similar enough to the baseline to confirm a finding",
                        SIMILARITY_THRESHOLD_SETTING,
                        DEFAULT_SIMILARITY_THRESHOLD))
                .build();
        api.userInterface().registerSettingsPanel(panel);
    }

    public double similarityThreshold() {
        if (panel == null) {
            return Double.parseDouble(DEFAULT_SIMILARITY_THRESHOLD);
        }
        try {
            return Double.parseDouble(panel.getString(SIMILARITY_THRESHOLD_SETTING).trim());
        } catch (NumberFormatException exc) {
            return Double.parseDouble(DEFAULT_SIMILARITY_THRESHOLD);
        }
    }

}
