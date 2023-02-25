package com.example.jwtauth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String TOKEN_PREFIX = "Bearer ";

    @Value("${security.jwt.tokenExpirationInHours}")
    private int tokenExpirationInHours;

    @Value("${security.jwt.secret}")
    private String secret;

    /**
     * Overload of {@link JwtService#generateToken(Map, UserDetails)} to create token
     * without the extra claims.
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(Collections.emptyMap(), userDetails);
    }

    /**
     * Generates a JWT using the user's username, roles. It uses the HS256 algorithm
     * to generate the token.
     */
    public String generateToken(Map<String, Objects> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(getExpirationDate())
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Extract username from the token.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Checks if the bearer token is not null, starts with the token prefix
     * and checks if it's not expired.
     */
    public String validateAndExtractJwt(String bearerToken) {
        if (bearerToken == null || !bearerToken.startsWith(TOKEN_PREFIX)) {
            throw new RuntimeException("Invalid token");
        }

        final String jwt = getPlainToken(bearerToken);
        if (isTokenExpired(jwt)) {
            throw new RuntimeException("Token expired");
        }

        return jwt;
    }

    /**
     * Extracts the expiration date from the token.
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extract the given claims for a given token
     */
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract all claims from the token.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Checks if the token has expired.
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Removed the bearer token prefix and returns the jwt.
     */
    private String getPlainToken(String bearerToken) {
        return bearerToken.substring(TOKEN_PREFIX.length());
    }

    /**
     * Generates the expiration date for the new JWT
     *
     * @return current date + expiration in hours
     */
    private Date getExpirationDate() {
        final Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.HOUR, tokenExpirationInHours);
        return calendar.getTime();
    }

    /**
     * Generates sign in key from secret by BASE64 decoding the secret and
     * hashing it with HMAC-SHA.
     */
    private Key getSignInKey() {
        final byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
