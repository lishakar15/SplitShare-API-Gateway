package com.lisha.Api.Gateway.filter;

import com.lisha.Api.Gateway.exception.HeaderException;
import com.lisha.Api.Gateway.utilities.JwtUtil;
import com.lisha.Api.Gateway.utilities.StringConstants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    JwtUtil jwtUtil;
    @Autowired
    RouteValidator routeValidator;
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException
    {
        if (routeValidator.isSecured.test(request))
        {
            try {
                String jwtToken = parseJwt(request);
                if (jwtToken == null) {
                    throw new HeaderException(StringConstants.HEADER_NOT_FOUND);
                }
                if (jwtToken != null) {
                    jwtUtil.validateJwtToken(jwtToken);
                }
            }
            catch (HeaderException ex)
            {
                LOGGER.error("Auth Token not found in request "+ex.getMessage());
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setHeader("Error-Message",ex.getMessage());
            }
        }
        filterChain.doFilter(request,response);
    }

    private String parseJwt(HttpServletRequest request) {
        return jwtUtil.getJwtFromHeader(request);
    }
}
