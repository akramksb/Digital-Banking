package ma.enset.secservice.security;

public class JWTUtil {
    public static final String SECRET = "MySecretKey_123";
    public static final String PREFIX = "Bearer ";
    public static final String AUTH_HEADER = "Authorization";
    public static final long EXPIRE_ACCESS_TOKEN = 5*60*1000;
    public static final long EXPIRE_REFRESH_TOKEN = 24*60*60*1000;
}
