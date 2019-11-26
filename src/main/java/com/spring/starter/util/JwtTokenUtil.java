package com.spring.starter.util;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenUtil implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 2015439508386430323L;
    private static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;
    
    @Value("${jwt.secret}")
    private String secret;
    
    /**
     * Retrieve user name from token
     * @param token
     * @return
     */
    public String getUserNameFromToken(String token) {
    	return getClaimFromToken(token, Claims :: getSubject);
    }
    
    /**
     * Returns the token that is applied with claim
     * @param token
     * @param claimsResolver
     * @return
     */
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
    	final Claims claims = getAllClaimsFromToken(token);
    	return claimsResolver.apply(claims);
    }
    
    /**
     * Retrieving any info using the secret key provided
     * @param token
     * @return
     */
    private Claims getAllClaimsFromToken(String token) {
    	return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }
    
    /**
     * Returns the expiration date
     * @param token
     * @return
     */
    private Date getExpirationDateFromToken(String token) {
    	return getClaimFromToken(token, Claims :: getExpiration);
    }
    
    /**
     * Validate the date of expiration
     * @param token
     * @return
     */
    private boolean isTokenExpired(String token) {
    	final Date expirationDate = getExpirationDateFromToken(token);
    	return expirationDate.before(new Date());
    }
    
    public String generateToken(UserDetails userDetails) {
    	Map<String, Object> claims = new HashMap<String, Object>();
    	return createToken(claims, userDetails.getUsername());
    }
    
    /**
     * Create the token
     * @param claims
     * @param subject
     * @return
     */
    private String createToken(Map<String, Object> claims, String subject) {
    	return Jwts.builder().
    			setClaims(claims).
    			setSubject(subject).
    			setIssuedAt(new Date(System.currentTimeMillis())).
    			setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000)).
    			signWith(SignatureAlgorithm.HS512, secret).compact();
    			
    }
    
    /**
     * Validate the token
     * @param token
     * @param userDetails
     * @return
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
    	final String userName = getUserNameFromToken(token);
    	return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
	
}
