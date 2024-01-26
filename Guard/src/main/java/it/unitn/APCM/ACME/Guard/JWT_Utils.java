package it.unitn.APCM.ACME.Guard;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import io.jsonwebtoken.security.Keys;
import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;

/**
 * The type Jwt utils.
 */
@Service
public class JWT_Utils {
    /**
     * The constant log.
     */
// Logger
	private static final Logger log = LoggerFactory.getLogger(Guard_RESTInterface.class);
    /**
     * The constant SECRET_KEY.
     */
// Secret key to encrypt and decrypt the token
    private static final SecretKey SECRET_KEY = Keys
            .hmacShaKeyFor((new CryptographyPrimitive().getSymmetricKey()).getEncoded());
    /**
     * The constant EXP_TIME.
     */
// Token expiration time => mills * seconds * minutes * hours
    private static final int EXP_TIME = 1000 * 60 * 30 * 1;

    /**
     * Extract username string.
     *
     * @param token the token
     * @return the string
     */
// Extract the username from the token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract date date.
     *
     * @param token the token
     * @return the date
     */
// Extract the expiration date from the token
    public Date extractDate(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extract claim t.
     *
     * @param <T>            the type parameter
     * @param token          the token
     * @param claimsResolver the claims resolver
     * @return the t
     */
// Extract the claims from the token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract groups string.
     *
     * @param token the token
     * @return the string
     */
// Extract the groups from the token
    public String extractGroups(String token) {
        final Claims claims = extractAllClaims(token);
        return (String) claims.get("groups");
    }

    /**
     * Extract admin int.
     *
     * @param token the token
     * @return the int
     */
// Extract the admin from the token
    public int extractAdmin(String token) {
        final Claims claims = extractAllClaims(token);
        return (int) claims.get("admin");
    }

    /**
     * Extract all claims claims.
     *
     * @param token the token
     * @return the claims
     */
// Extract all the claims from the token
    private Claims extractAllClaims(String token) {
        return Jwts.parser().verifyWith(SECRET_KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Is token expired boolean.
     *
     * @param token the token
     * @return the boolean
     */
    private Boolean isTokenExpired(String token) {
        return extractDate(token).before(new Date());
    }

    /**
     * Generate token string.
     *
     * @param userDetails the user details
     * @return the string
     */
// Generate the token
    public String generateToken(User userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("groups", userDetails.getGroups());
        claims.put("admin", userDetails.getAdmin());
        return createToken(claims, userDetails.getEmail());
    }

    /**
     * Create token string.
     *
     * @param claims  the claims
     * @param subject the subject
     * @return the string
     */
// Create the token
    private String createToken(Map<String, Object> claims, String subject) {
        long start_time = System.currentTimeMillis();
        return Jwts.builder().claims(claims).subject(subject).issuedAt(new Date(start_time))
                .expiration(new Date(start_time + EXP_TIME))
                .signWith(SECRET_KEY).compact();
    }

    /**
     * Validate token boolean.
     *
     * @param token the token
     * @param email the email
     * @return the boolean
     */
// Validate the token
    public Boolean validateToken(String token, String email) {
        boolean res = false;
        try{
            final String username = extractUsername(token);
            res = (username.equals(email) && !isTokenExpired(token));
        } catch(Exception e){
            log.error("Error in validating JWT");
        }

        return res;
    }
}
