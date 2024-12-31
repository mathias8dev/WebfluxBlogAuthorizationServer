package com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantPassword

import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.getParameters
import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantPassword.AuthorizationGrantTypePassword.GRANT_PASSWORD
import jakarta.annotation.Nullable
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.util.StringUtils


class OAuth2GrantPasswordAuthenticationConverter : AuthenticationConverter {

    private val logger = LoggerFactory.getLogger(OAuth2GrantPasswordAuthenticationConverter::class.java)

    @Nullable
    override fun convert(request: HttpServletRequest): Authentication? {
        val grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE)

        if (!GRANT_PASSWORD.value.equals(grantType)) {
            return null
        }

        val parameters = getParameters(request) // MultiValueMap

        // scope (OPTIONAL)
        val scope = parameters.getFirst(OAuth2ParameterNames.SCOPE)
        if (!scope.isNullOrBlank() && parameters[OAuth2ParameterNames.SCOPE]!!.size != 1) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        // username (REQUIRED)
        val username = parameters.getFirst(OAuth2ParameterNames.USERNAME)
        if (username.isNullOrBlank() || parameters[OAuth2ParameterNames.USERNAME]!!.size != 1) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        // password (REQUIRED)
        val password = parameters.getFirst(OAuth2ParameterNames.PASSWORD)
        if (password.isNullOrBlank() || parameters[OAuth2ParameterNames.PASSWORD]!!.size != 1
        ) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
        }


        val requestedScopes = if (!scope.isNullOrBlank()) {
            StringUtils.delimitedListToStringArray(scope, " ").toSet()
        } else null

        logger.debug("The requestedScopes is {}", requestedScopes)

        val additionalParameters = parameters.entries.asSequence()
            .filter { entry: Map.Entry<String, List<String>?> ->
                (OAuth2ParameterNames.GRANT_TYPE != entry.key
                        && OAuth2ParameterNames.SCOPE != entry.key
                        && OAuth2ParameterNames.PASSWORD != entry.key
                        && OAuth2ParameterNames.USERNAME != entry.key)
            }
            .map { entry -> entry.key to entry.value?.firstOrNull() }
            .toMap()

        val clientPrincipal: Authentication = SecurityContextHolder.getContext().authentication

        return GrantPasswordAuthenticationToken(
            clientPrincipal, username, password, requestedScopes, additionalParameters
        )
    }

}