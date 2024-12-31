package com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantOtt

import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantOtt.AuthorizationGrantTypeOtt.GRANT_OTT
import jakarta.annotation.Nullable
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken
import org.springframework.util.Assert


class GrantOttAuthenticationToken(
    clientPrincipal: Authentication?,
    username: String,
    token: String,
    @Nullable scopes: Set<String>?,
    @Nullable additionalParameters: Map<String, Any?>?
) : OAuth2AuthorizationGrantAuthenticationToken(GRANT_OTT, clientPrincipal, additionalParameters) {
    val username: String
    val ott: String
    val scopes: Set<String?>

    init {
        Assert.hasText(username, "username cannot be empty")
        Assert.hasText(token, "ott cannot be empty")
        this.username = username
        this.ott = token
        this.scopes = scopes ?: emptySet<String>()
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}