package com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken

class OpaqueTokenAuthenticationProvider : AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication? {
        val bearer = authentication as BearerTokenAuthenticationToken
        return null
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return BearerTokenAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

}