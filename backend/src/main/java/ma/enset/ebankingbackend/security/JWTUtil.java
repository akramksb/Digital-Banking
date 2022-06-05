package ma.enset.ebankingbackend.security;

public class JWTUtil {
    public static final String SECRET = "SaadSecret";
    public static final String AUTH_HEADER = "Authorization";
    public static final String PREFIX = "Bearer ";
    public static final long EXPIRE_ACCESS_TOKEN = 20*60*1000;
    public static final long EXPIRE_REFRESH_TOKEN = 20*60*1000;
}
