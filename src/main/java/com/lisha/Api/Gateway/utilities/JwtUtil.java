package com.lisha.Api.Gateway.utilities;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.stereotype.Component;

import java.security.Key;

@Component
public class JwtUtil {

    //Add the method to validate if the JWT token is valid or not
    public static final String SECRET = PropertiesReader.getProperty(StringConstants.SECRET);

    public void validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(SECRET).parseClaimsJws(authToken);
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException(StringConstants.UNAUTHORIZED_ACCESS, ex);
        } catch (ExpiredJwtException ex) {
            throw new CredentialsExpiredException(StringConstants.TOKEN_EXPIRED, ex);
        }

    }
    public boolean validateInviteToken(String authToken) throws ExpiredJwtException {
        try {
            Jwts.parser().setSigningKey(SECRET).parseClaimsJws(authToken);
            return true;
        } catch (ExpiredJwtException e) {
            throw e;
        } catch (JwtException e) {
            throw new BadCredentialsException("Invalid invite token");
        }
    }
    public String getTokenType(String authToken)
    {
        Claims claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(authToken).getBody();
        return claims.get("type",String.class);

    }
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET));
    }
}
