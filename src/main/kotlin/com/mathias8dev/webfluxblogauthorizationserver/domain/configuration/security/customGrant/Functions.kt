package com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*

internal fun getParameters(request: HttpServletRequest): MultiValueMap<String, String> {
    val parameterMap = request.parameterMap
    val parameters: MultiValueMap<String, String> = LinkedMultiValueMap(parameterMap.size)
    parameterMap.forEach { (key: String, values: Array<String?>) ->
        if (values.isNotEmpty()) {
            for (value in values) {
                parameters.add(key, value)
            }
        }
    }
    return parameters
}


internal const val ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2"
internal val ID_TOKEN_TOKEN_TYPE = OAuth2TokenType(OidcParameterNames.ID_TOKEN)

internal fun getAuthenticatedClientElseThrowInvalidClient(authentication: Authentication): OAuth2ClientAuthenticationToken {
    var clientPrincipal: OAuth2ClientAuthenticationToken? = null

    if (OAuth2ClientAuthenticationToken::class.java.isAssignableFrom(authentication.principal.javaClass)) {
        clientPrincipal = authentication.principal as OAuth2ClientAuthenticationToken
    }

    if (clientPrincipal != null && clientPrincipal.isAuthenticated) {
        return clientPrincipal
    }

    throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)
}

@Throws(NoSuchAlgorithmException::class)
internal fun createHash(value: String): String {
    val md: MessageDigest = MessageDigest.getInstance("SHA-256")
    val digest: ByteArray = md.digest(value.toByteArray(StandardCharsets.UTF_8))
    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
}