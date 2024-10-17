package com.lisha.Api.Gateway.filter;

import ch.qos.logback.core.hook.DelayingShutdownHook;
import com.lisha.Api.Gateway.exception.HeaderException;
import com.lisha.Api.Gateway.utilities.JwtUtil;
import com.lisha.Api.Gateway.utilities.StringConstants;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {
    @Autowired
    JwtUtil jwtUtil;
    @Autowired
    RouteValidator routeValidator;
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    public static class Config {
        private String role;

        public Config() {
        }

        public Config(String role) {
            this.role = role;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }
    }

    public JwtAuthenticationFilter() {
        super(Config.class);
    }
    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (routeValidator.isSecured.test(exchange.getRequest())) {
                try {
                    if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                        throw new HeaderException(StringConstants.HEADER_NOT_FOUND);
                    }
                    String jwtToken = StringConstants.EMPTY_STRING;
                    String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                    if (authHeader != null && authHeader.startsWith(StringConstants.BEARER_HEADER)) {
                        jwtToken = authHeader.substring(7);
                    }
                    jwtUtil.validateJwtToken(jwtToken);

                } catch (BadCredentialsException | HeaderException | CredentialsExpiredException exception) {
                    if(routeValidator.isInviteExchange.test(exchange.getRequest()))
                    {
                        return Mono.defer(() -> {
                            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                            exchange.getResponse().getHeaders().add("Error-Message", "Invalid or expired invite");
                            return exchange.getResponse().setComplete();
                        });
                    }
                    else {
                        return Mono.defer(() -> {
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            exchange.getResponse().getHeaders().add("Error-Message", exception.getMessage());
                            return exchange.getResponse().setComplete();
                        });
                    }

                }
            }
            return chain.filter(exchange);
        });
    }
}
