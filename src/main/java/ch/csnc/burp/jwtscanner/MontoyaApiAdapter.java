package ch.csnc.burp.jwtscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * This class is designed for better testability.
 * It mocks certain functionalities if {@link MontoyaApi} is not available, which occurs when the code is not running
 * in Burp Suite. It can be used where a simple alternative to {@link MontoyaApi} can be provided, but one should not
 * reimplement {@link MontoyaApi} completely. Use and extend it where appropriate.
 */
public class MontoyaApiAdapter {

    private final LoggingAdapter logging;
    private final PersistenceAdapter persistence;

    public MontoyaApiAdapter() {
        this.logging = new LoggingAdapter();
        this.persistence = new PersistenceAdapter();
    }

    public MontoyaApiAdapter(MontoyaApi api) {
        this.logging = new LoggingAdapter(api.logging());
        this.persistence = new PersistenceAdapter(api.persistence());
    }

    public LoggingAdapter logging() {
        return this.logging;
    }

    public PersistenceAdapter persistence() {
        return this.persistence;
    }

    public static class LoggingAdapter {

        private final Logging logging;

        public LoggingAdapter() {
            this(null);
        }

        public LoggingAdapter(Logging logging) {
            this.logging = logging;
        }

        public void logToError(Throwable throwable) {
            if (this.logging != null) {
                this.logging.logToError(throwable);
            } else {
                throwable.printStackTrace(System.err);
            }
        }

    }

    public static class PersistenceAdapter {

        private final PersistedObjectWrapper extensionData;

        public PersistenceAdapter() {
            this.extensionData = new PersistedObjectWrapper();
        }

        public PersistenceAdapter(Persistence persistence) {
            this.extensionData = new PersistedObjectWrapper(persistence.extensionData());
        }

        public PersistedObjectWrapper extensionData() {
            return this.extensionData;
        }

    }

    public static class PersistedObjectWrapper {

        private final PersistedObject persistedObject;
        private final Map<String, byte[]> bytesMap;

        public PersistedObjectWrapper() {
            this(null);
        }

        public PersistedObjectWrapper(PersistedObject persistedObject) {
            this.persistedObject = persistedObject;
            this.bytesMap = new HashMap<>();
        }

        public void setByteArray(String key, byte[] bytes) {
            if (this.persistedObject != null) {
                this.persistedObject.setByteArray(key, ByteArray.byteArray(bytes));
            } else {
                this.bytesMap.put(key, bytes);
            }
        }

        public byte[] getByteArray(String key) {
            if (this.persistedObject != null) {
                return Optional.ofNullable(this.persistedObject.getByteArray(key))
                        .map(ByteArray::getBytes)
                        .orElse(null);
            } else {
                return this.bytesMap.get(key);
            }
        }

    }

}
