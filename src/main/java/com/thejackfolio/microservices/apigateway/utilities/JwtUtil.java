package com.thejackfolio.microservices.apigateway.utilities;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Arrays;
import java.util.List;

@Service
public class JwtUtil {

    public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";

    public void validateToken(final String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token);
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException("INVALID_CREDENTIALS", ex);
        } catch (ExpiredJwtException ex) {
            throw new BadCredentialsException("EXPIRED_CREDENTIALS", ex);
        }
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public List<String> getRolesFromToken(String authToken) {
        List<String> roles = null;
        Claims claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(authToken).getBody();
        Boolean isParticipant = claims.get("isParticipant", Boolean.class);
        Boolean isOrganizer = claims.get("isOrganizer", Boolean.class);
        Boolean isAdmin = claims.get("isAdmin", Boolean.class);
        if (isParticipant != null && isParticipant == true) {
            roles = Arrays.asList("PARTICIPANT");
        }
        if (isOrganizer != null && isOrganizer == true) {
            roles = Arrays.asList("ORGANIZER");
        }
        if (isAdmin != null && isAdmin == true) {
            roles = Arrays.asList("ADMIN");
        }
        return roles;
    }
}
