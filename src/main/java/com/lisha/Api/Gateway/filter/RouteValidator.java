package com.lisha.Api.Gateway.filter;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouteValidator {

    public static final List<String> openApiEndpoints = List.of(
            "/user/register-user",
            "/user/contact-support",
            "/user/logout"
    );

    public Predicate<HttpServletRequest> isSecured =
            request -> openApiEndpoints.stream().noneMatch(uri -> request.getRequestURI().contains(uri));
}
