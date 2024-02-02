package it.unitn.APCM.ACME.Guard.Objects;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import io.jsonwebtoken.security.Keys;
import it.unitn.APCM.ACME.Guard.Guard_RESTInterface;
import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;

/**
 * The type JWT utils.
 */
@Service
public class JWT_Utils {
	/**
	 * The constant logger.
	 */
	private static final Logger log = LoggerFactory.getLogger(Guard_RESTInterface.class);
	/**
	 * Secret key to encrypt and decrypt the token.
	 */
	private static final SecretKey SECRET_KEY = Keys
            .hmacShaKeyFor((new CryptographyPrimitive().getSymmetricKey()).getEncoded());
	/**
	 * Token expiration time => mills * seconds * minutes * hours.
	 */
	private static final int EXP_TIME = 1000 * 60 * 30 * 1;

	/**
	 * Extract username string from the token.
	 *
	 * @param token the token
	 * @return the string
	 */
	public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

	/**
	 * Extract expiration date from the token.
	 *
	 * @param token the token
	 * @return the date
	 */
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
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

	/**
	 * Extract the groups of the user from the token.
	 *
	 * @param token the token
	 * @return the string
	 */
	public String extractGroups(String token) {
        final Claims claims = extractAllClaims(token);
        return (String) claims.get("groups");
    }

	/**
	 * Extract the admin of the user from the token.
	 *
	 * @param token the token
	 * @return the int
	 */
	public int extractAdmin(String token) {
        final Claims claims = extractAllClaims(token);
        return (int) claims.get("admin");
    }

	/**
	 * Extract all claims from the token.
	 *
	 * @param token the token
	 * @return the claims
	 */
	private Claims extractAllClaims(String token) {
        return Jwts.parser().verifyWith(SECRET_KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

	/**
	 * Check if the token is expired.
	 *
	 * @param token the token
	 * @return the boolean
	 */
	private Boolean isTokenExpired(String token) {
        return extractDate(token).before(new Date());
    }

	/**
	 * Generate token.
	 *
	 * @param userDetails the user details
	 * @return the string
	 */
	public String generateToken(User userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("groups", userDetails.getGroups());
        claims.put("admin", userDetails.getAdmin());
        return createToken(claims, userDetails.getEmail());
    }

	/**
	 * Create token.
	 *
	 * @param claims  the claims
	 * @param subject the subject
	 * @return the string
	 */
	private String createToken(Map<String, Object> claims, String subject) {
        long start_time = System.currentTimeMillis();
        return Jwts.builder().claims(claims).subject(subject).issuedAt(new Date(start_time))
                .expiration(new Date(start_time + EXP_TIME))
                .signWith(SECRET_KEY).compact();
    }

	/**
	 * Validate the token.
	 *
	 * @param token the token
	 * @param email the email
	 * @return the boolean
	 */
	public Boolean validateToken(String token, String email) {
        boolean res = false;
        try {
            final String username = extractUsername(token);
            res = (username.equals(email) && !isTokenExpired(token));
        } catch (Exception e) {
            log.error("Error in validating JWT");
        }

        return res;
    }
}
