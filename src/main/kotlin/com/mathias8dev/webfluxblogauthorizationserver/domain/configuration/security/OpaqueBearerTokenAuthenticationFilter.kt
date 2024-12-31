package com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationManagerResolver
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter


class OpaqueBearerTokenAuthenticationFilter : BearerTokenAuthenticationFilter {

    constructor(
        authenticationManagerResolver: AuthenticationManagerResolver<HttpServletRequest>
    ) : super(authenticationManagerResolver)

    constructor(authenticationManager: AuthenticationManager) : super(authenticationManager)

}