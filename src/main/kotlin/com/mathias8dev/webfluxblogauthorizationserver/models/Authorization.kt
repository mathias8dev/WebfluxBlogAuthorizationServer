package com.mathias8dev.webfluxblogauthorizationserver.models

import com.mathias8dev.webfluxblogauthorizationserver.domain.JacksonUtils
import com.mathias8dev.webfluxblogauthorizationserver.domain.JacksonUtils.parseMap
import com.mathias8dev.webfluxblogauthorizationserver.domain.JacksonUtils.writeMap
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.hibernate.Length
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2DeviceCode
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.OAuth2UserCode
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.util.StringUtils
import java.time.Instant
import java.util.function.Consumer


@Entity
@Table(name = "authorization")
class Authorization(
    @Id
    @Column
    var id: String? = null,
    var registeredClientId: String? = null,
    var principalName: String? = null,
    var authorizationGrantType: String? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var authorizedScopes: String? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var attributes: String? = null,

    @Column(length = 500)
    var
    state: String? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var authorizationCodeValue: String? = null,
    var authorizationCodeIssuedAt: Instant? = null,
    var authorizationCodeExpiresAt: Instant? = null,
    var authorizationCodeMetadata: String? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var accessTokenValue: String? = null,
    var accessTokenIssuedAt: Instant? = null,
    var accessTokenExpiresAt: Instant? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var accessTokenMetadata: String? = null,
    var accessTokenType: String? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var accessTokenScopes: String? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var refreshTokenValue: String? = null,
    var refreshTokenIssuedAt: Instant? = null,
    var refreshTokenExpiresAt: Instant? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var refreshTokenMetadata: String? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var oidcIdTokenValue: String? = null,
    var oidcIdTokenIssuedAt: Instant? = null,
    var oidcIdTokenExpiresAt: Instant? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var oidcIdTokenMetadata: String? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var oidcIdTokenClaims: String? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var userCodeValue: String? = null,
    var userCodeIssuedAt: Instant? = null,
    var userCodeExpiresAt: Instant? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var userCodeMetadata: String? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var deviceCodeValue: String? = null,
    var deviceCodeIssuedAt: Instant? = null,
    var deviceCodeExpiresAt: Instant? = null,

    @Column(length = Length.LOB_DEFAULT, nullable = true)
    var deviceCodeMetadata: String? = null
) {


    companion object {

        val objectMapper = JacksonUtils.objectMapper(Authorization::class.java.classLoader)

        fun toObject(entity: Authorization, registeredClient: RegisteredClient): OAuth2Authorization {


            val builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(entity.id)
                .principalName(entity.principalName)
                .apply {
                    entity.authorizationGrantType?.let {
                        authorizationGrantType(
                            Client.resolveAuthorizationGrantType(
                                it
                            )
                        )
                    }
                }
                .authorizedScopes(entity.authorizedScopes?.split(",")?.toHashSet())
                .attributes { attributes: MutableMap<String?, Any?> ->
                    entity.attributes?.let {
                        objectMapper.parseMap(it)?.let { it1 ->
                            attributes.putAll(
                                it1
                            )
                        }
                    }
                }
            if (entity.state != null) {
                builder.attribute(OAuth2ParameterNames.STATE, entity.state)
            }

            if (entity.authorizationCodeValue != null) {
                val authorizationCode = OAuth2AuthorizationCode(
                    entity.authorizationCodeValue,
                    entity.authorizationCodeIssuedAt,
                    entity.authorizationCodeExpiresAt
                )
                builder.token(authorizationCode) { metadata: MutableMap<String?, Any?> ->
                    entity.authorizationCodeMetadata?.let { objectMapper.parseMap(it) }?.let {
                        metadata.putAll(
                            it
                        )
                    }
                }
            }

            if (entity.accessTokenValue != null) {
                val accessToken = OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    entity.accessTokenValue,
                    entity.accessTokenIssuedAt,
                    entity.accessTokenExpiresAt,
                    StringUtils.commaDelimitedListToSet(entity.accessTokenScopes).toHashSet()
                )
                builder.token(
                    accessToken
                ) { metadata: MutableMap<String?, Any?> ->
                    entity.accessTokenMetadata?.let {
                        objectMapper.parseMap(it)?.let { it1 ->
                            metadata.putAll(
                                it1
                            )
                        }
                    }
                }
            }

            if (entity.refreshTokenValue != null) {
                val refreshToken = OAuth2RefreshToken(
                    entity.refreshTokenValue,
                    entity.refreshTokenIssuedAt,
                    entity.refreshTokenExpiresAt
                )
                builder.token(
                    refreshToken
                ) { metadata: MutableMap<String?, Any?> ->
                    entity.refreshTokenMetadata?.let {
                        objectMapper.parseMap(it)?.let { it1 ->
                            metadata.putAll(
                                it1
                            )
                        }
                    }
                }
            }

            if (entity.oidcIdTokenValue != null) {
                val idToken = OidcIdToken(
                    entity.oidcIdTokenValue,
                    entity.oidcIdTokenIssuedAt,
                    entity.oidcIdTokenExpiresAt,
                    entity.oidcIdTokenClaims?.let { objectMapper.parseMap(it) }
                )
                builder.token(
                    idToken
                ) { metadata: MutableMap<String?, Any?> ->
                    entity.oidcIdTokenMetadata?.let {
                        objectMapper.parseMap(it)?.let { it1 ->
                            metadata.putAll(
                                it1
                            )
                        }
                    }
                }
            }

            if (entity.userCodeValue != null) {
                val userCode = OAuth2UserCode(
                    entity.userCodeValue,
                    entity.userCodeIssuedAt,
                    entity.userCodeExpiresAt
                )
                builder.token(
                    userCode
                ) { metadata: MutableMap<String?, Any?> ->
                    entity.userCodeMetadata?.let {
                        objectMapper.parseMap(it)?.let { it1 ->
                            metadata.putAll(
                                it1
                            )
                        }
                    }
                }
            }

            if (entity.deviceCodeValue != null) {
                val deviceCode = OAuth2DeviceCode(
                    entity.deviceCodeValue,
                    entity.deviceCodeIssuedAt,
                    entity.deviceCodeExpiresAt
                )
                builder.token(
                    deviceCode
                ) { metadata: MutableMap<String?, Any?> ->
                    entity.deviceCodeMetadata?.let {
                        objectMapper.parseMap(it)?.let { it1 ->
                            metadata.putAll(
                                it1
                            )
                        }
                    }
                }
            }

            return builder.build()
        }

        fun toEntity(authorization: OAuth2Authorization): Authorization {
            val entity = Authorization()
            entity.id = authorization.id
            entity.registeredClientId = authorization.registeredClientId
            entity.principalName = authorization.principalName
            entity.authorizationGrantType = authorization.authorizationGrantType.value
            entity.authorizedScopes = StringUtils.collectionToDelimitedString(authorization.authorizedScopes, ",")
            entity.attributes = objectMapper.writeMap(authorization.attributes)
            entity.state = authorization.getAttribute(OAuth2ParameterNames.STATE)

            val authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode::class.java)
            setTokenValues(
                token = authorizationCode,
                tokenValueConsumer = { entity.authorizationCodeValue = it },
                issuedAtConsumer = { entity.authorizationCodeIssuedAt = it },
                expiresAtConsumer = { entity.authorizationCodeExpiresAt = it },
                metadataConsumer = { entity.authorizationCodeMetadata = it }
            )

            val accessToken =
                authorization.getToken(OAuth2AccessToken::class.java)
            setTokenValues(
                token = accessToken,
                tokenValueConsumer = { entity.accessTokenValue = it },
                issuedAtConsumer = { entity.accessTokenIssuedAt = it },
                expiresAtConsumer = { entity.accessTokenExpiresAt = it },
                metadataConsumer = { entity.accessTokenMetadata = it }
            )
            if (accessToken != null && accessToken.token.scopes != null) {
                entity.accessTokenScopes = StringUtils.collectionToDelimitedString(accessToken.token.scopes, ",")
            }

            val refreshToken =
                authorization.getToken(OAuth2RefreshToken::class.java)
            setTokenValues(
                token = refreshToken,
                tokenValueConsumer = { entity.refreshTokenValue = it },
                issuedAtConsumer = { entity.refreshTokenIssuedAt = it },
                expiresAtConsumer = { entity.refreshTokenExpiresAt = it },
                metadataConsumer = { entity.refreshTokenMetadata = it }
            )

            val oidcIdToken =
                authorization.getToken(OidcIdToken::class.java)
            setTokenValues(
                token = oidcIdToken,
                tokenValueConsumer = { entity.oidcIdTokenValue = it },
                issuedAtConsumer = { entity.oidcIdTokenIssuedAt = it },
                expiresAtConsumer = { entity.oidcIdTokenExpiresAt = it },
                metadataConsumer = { entity.oidcIdTokenMetadata = it }
            )
            if (oidcIdToken != null) {
                entity.oidcIdTokenClaims = objectMapper.writeMap(oidcIdToken.claims)
            }

            val userCode = authorization.getToken(OAuth2UserCode::class.java)
            setTokenValues(
                token = userCode,
                tokenValueConsumer = { entity.userCodeValue = it },
                issuedAtConsumer = { entity.userCodeIssuedAt = it },
                expiresAtConsumer = { entity.userCodeExpiresAt = it },
                metadataConsumer = { entity.userCodeMetadata = it }
            )

            val deviceCode = authorization.getToken(OAuth2DeviceCode::class.java)
            setTokenValues(
                token = deviceCode,
                tokenValueConsumer = { entity.deviceCodeValue = it },
                issuedAtConsumer = { entity.deviceCodeIssuedAt = it },
                expiresAtConsumer = { entity.deviceCodeExpiresAt = it },
                metadataConsumer = { entity.deviceCodeMetadata = it }
            )

            return entity
        }

        private fun setTokenValues(
            token: OAuth2Authorization.Token<*>?,
            tokenValueConsumer: Consumer<String?>,
            issuedAtConsumer: Consumer<Instant?>,
            expiresAtConsumer: Consumer<Instant?>,
            metadataConsumer: Consumer<String?>
        ) {
            if (token != null) {
                val oAuth2Token = token.token
                tokenValueConsumer.accept(oAuth2Token.tokenValue)
                issuedAtConsumer.accept(oAuth2Token.issuedAt)
                expiresAtConsumer.accept(oAuth2Token.expiresAt)
                metadataConsumer.accept(objectMapper.writeMap(token.metadata))
            }
        }
    }
}