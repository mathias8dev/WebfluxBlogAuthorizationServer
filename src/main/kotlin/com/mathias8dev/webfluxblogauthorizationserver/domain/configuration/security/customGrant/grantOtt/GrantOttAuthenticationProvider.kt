package com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantOtt


import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.*
import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantOtt.AuthorizationGrantTypeOtt.GRANT_OTT
import com.mathias8dev.webfluxblogauthorizationserver.services.OneTimeTokenValidator
import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.session.SessionInformation
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import java.security.Principal
import java.util.*


class GrantOttAuthenticationProvider(
    private val authorizationService: OAuth2AuthorizationService,
    private val tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>,
    private val oneTimeTokenValidator: OneTimeTokenValidator,
    private val passwordEncoder: PasswordEncoder
) : AuthenticationProvider {

    private val logger: Log = LogFactory.getLog(javaClass)

    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication {
        val ottAuthenticationToken = authentication as GrantOttAuthenticationToken

        // Ensure the client is authenticated
        val clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(ottAuthenticationToken)

        val registeredClient = clientPrincipal.registeredClient

        if (logger.isDebugEnabled) {
            logger.trace("Retrieved registered client")
        }

        // Ensure the client is configured to use this authorization grant type
        logger.info("The registered client is $registeredClient")
        if (registeredClient == null || !registeredClient.authorizationGrantTypes.contains(GRANT_OTT)) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
        }

        // Ensure the client has the requested scopes
        if (!registeredClient.scopes.containsAll(ottAuthenticationToken.scopes)) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE)
        }

        if (logger.isTraceEnabled) {
            logger.trace("Retrieved authorization with username and ott")
        }

        val username: String = ottAuthenticationToken.username
        val oneTimeToken: String = ottAuthenticationToken.ott

        val user = runCatching {
            oneTimeTokenValidator.validateOttAndGetUser(username, oneTimeToken) as CustomUserDetails
        }.getOrElse {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED)
        }

        if (!user.isEnabled || !user.isAccountNonExpired || !user.isAccountNonLocked || !user.isCredentialsNonExpired) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED)
        }


        (SecurityContextHolder.getContext().authentication as OAuth2ClientAuthenticationToken).details =
            CustomUserDetails(username, user.authorities)

        val tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(clientPrincipal)
            .authorizationServerContext( // Issuer contains here
                AuthorizationServerContextHolder.getContext()
            )
            .authorizedScopes(ottAuthenticationToken.scopes)
            .authorizationGrantType(GRANT_OTT)
            .authorizationGrant(ottAuthenticationToken)

        // Generate the access token
        var tokenContext: OAuth2TokenContext = tokenContextBuilder
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .build()

        val generatedAccessToken = tokenGenerator.generate(tokenContext)

        if (generatedAccessToken == null) {
            val error = OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR,
                "The token generator failed to generate the access token.", ERROR_URI
            )
            throw OAuth2AuthenticationException(error)
        }

        if (logger.isTraceEnabled) {
            logger.trace("Generated access token")
        }

        // ----- Access token -----
        val accessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.tokenValue,
            generatedAccessToken.issuedAt,
            generatedAccessToken.expiresAt,
            tokenContext.authorizedScopes
        )

        logger.info("The access token is ${accessToken.tokenValue}")


        // Initialize the OAuth2Authorization
        val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .attribute(Principal::class.java.name, clientPrincipal)
            .principalName(clientPrincipal.name)
            .authorizationGrantType(GRANT_OTT)
            .authorizedScopes(registeredClient.scopes)

        if (generatedAccessToken is ClaimAccessor) {
            authorizationBuilder.token(
                accessToken
            ) { metadata: MutableMap<String?, Any?> ->
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] =
                    (generatedAccessToken as ClaimAccessor).claims
            }
        } else {
            authorizationBuilder.accessToken(accessToken)
        }

        // ----- Refresh token -----
        var refreshToken: OAuth2RefreshToken? = null

        if (registeredClient.authorizationGrantTypes.contains(AuthorizationGrantType.REFRESH_TOKEN)
            && clientPrincipal.clientAuthenticationMethod != ClientAuthenticationMethod.NONE
        ) {
            tokenContext = tokenContextBuilder
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .build()

            val generatedRefreshToken = tokenGenerator.generate(tokenContext)
            logger.info("The generated refresh token is ${generatedRefreshToken?.tokenValue}")

            if (generatedRefreshToken !is OAuth2RefreshToken) {
                val error = OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the refresh token.", ERROR_URI
                )
                throw OAuth2AuthenticationException(error)
            }

            refreshToken = generatedRefreshToken
            authorizationBuilder.refreshToken(refreshToken)
        }





        if (logger.isTraceEnabled) {
            logger.trace("Saved authorization")
        }

        if (logger.isTraceEnabled) {
            logger.trace("Authenticated token request")
        }


        // ----- ID token -----
        val idToken: OidcIdToken?
        if (ottAuthenticationToken.scopes.contains(OidcScopes.OPENID)) {
            val sessionInformation = SessionInformation(
                ottAuthenticationToken.principal,
                createHash(UUID.randomUUID().toString()), Date()
            )
            tokenContextBuilder.put(SessionInformation::class.java, sessionInformation)


            // @formatter:off
            tokenContext = tokenContextBuilder
                .tokenType(ID_TOKEN_TOKEN_TYPE)
                .authorization(authorizationBuilder.build()) // ID token customizer may need access to the access token and/or refresh token
                .build()
            // @formatter:on
            val generatedIdToken = tokenGenerator.generate(tokenContext)
            if (generatedIdToken !is Jwt) {
                val error = OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the ID token.", OAuth2ParameterNames.ERROR_URI
                )
                throw OAuth2AuthenticationException(error)
            }

            if (logger.isTraceEnabled) {
                logger.trace("Generated id token")
            }

            logger.info("The generated idToken's claims are ${generatedIdToken.claims}")

            idToken = OidcIdToken(
                generatedIdToken.tokenValue, generatedIdToken.issuedAt,
                generatedIdToken.expiresAt, generatedIdToken.claims
            )
            authorizationBuilder.token(
                idToken
            ) { metadata: MutableMap<String?, Any?> ->
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = idToken.claims
            }
        } else {
            idToken = null
        }

        val additionalParameters = mutableMapOf<String, Any>()
        idToken?.let {
            additionalParameters[OidcParameterNames.ID_TOKEN] = it.tokenValue
        }


        if (logger.isTraceEnabled) {
            logger.trace("Authenticated token request")
        }
        val authorization = authorizationBuilder.build()
        authorizationService.save(authorization)

        return OAuth2AccessTokenAuthenticationToken(
            registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters
        )
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return GrantOttAuthenticationToken::class.java.isAssignableFrom(authentication)
    }


}