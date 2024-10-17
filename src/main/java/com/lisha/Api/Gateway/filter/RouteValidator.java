package com.lisha.Api.Gateway.filter;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouteValidator {

    public static final List<String> openApiEndpoints = List.of(
            "/user/register-user",
            "/user/login-user",
            "/user/contact-support",
            "/user/logout",
            "/user/invite-link"
    );
    public static final List<String> inviteEndPoints = List.of(
            "user/accept-invite",
            "/group/join-group"
    );


    public Predicate<ServerHttpRequest> isSecured =
            request -> openApiEndpoints.stream().noneMatch(uri -> request.getURI().getPath().contains(uri));

    public Predicate<ServerHttpRequest> isInviteExchange =
            request -> inviteEndPoints.stream().anyMatch(uri -> request.getURI().getPath().contains(uri));

}
