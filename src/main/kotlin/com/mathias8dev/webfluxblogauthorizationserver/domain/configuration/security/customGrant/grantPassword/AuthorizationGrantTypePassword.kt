package com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantPassword

import org.springframework.security.oauth2.core.AuthorizationGrantType


object AuthorizationGrantTypePassword {
    val GRANT_PASSWORD: AuthorizationGrantType = AuthorizationGrantType("grant_password")
}