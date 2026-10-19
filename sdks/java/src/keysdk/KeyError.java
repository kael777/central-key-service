package keysdk;

/** 共用錯誤碼，與 Go／PHP／Node 完全一致。 */
public class KeyError extends RuntimeException {
    public static final String FORMAT = "ERR_FORMAT";
    public static final String UNKNOWN_KID = "ERR_UNKNOWN_KID";
    public static final String KEY = "ERR_KEY";
    public static final String AUTH = "ERR_AUTH";
    public static final String STALE = "ERR_STALE";
    public static final String UNAVAILABLE = "ERR_UNAVAILABLE";
    public static final String UNAUTHORIZED = "ERR_UNAUTHORIZED";
    public static final String POLICY_DISABLED = "ERR_POLICY_DISABLED";

    private final String code;

    public KeyError(String code, String message) {
        super(message);
        this.code = code;
    }

    public KeyError(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
