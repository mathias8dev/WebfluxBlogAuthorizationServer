package com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantPassword

import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantPassword.AuthorizationGrantTypePassword.GRANT_PASSWORD
import jakarta.annotation.Nullable
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken
import org.springframework.util.Assert


class GrantPasswordAuthenticationToken(
    clientPrincipal: Authentication?,
    username: String,
    password: String,
    @Nullable scopes: Set<String>?,
    @Nullable additionalParameters: Map<String, Any?>?
) : OAuth2AuthorizationGrantAuthenticationToken(GRANT_PASSWORD, clientPrincipal, additionalParameters) {
    val username: String
    val password: String
    val scopes: Set<String?>

    init {
        Assert.hasText(username, "username cannot be empty")
        Assert.hasText(password, "password cannot be empty")
        this.username = username
        this.password = password
        this.scopes = scopes ?: emptySet<String>()
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}