package com.mathias8dev.webfluxblogauthorizationserver.models

import com.mathias8dev.webfluxblogauthorizationserver.domain.JacksonUtils
import com.mathias8dev.webfluxblogauthorizationserver.domain.JacksonUtils.parseMap
import com.mathias8dev.webfluxblogauthorizationserver.domain.JacksonUtils.writeMap
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.util.StringUtils
import java.time.Instant


@Entity
@Table(name = "client")
class Client(
    @Id
    var id: String? = null,
    var clientId: String? = null,
    var clientIdIssuedAt: Instant? = null,
    var clientSecret: String? = null,
    var clientSecretExpiresAt: Instant? = null,
    var clientName: String? = null,

    @Column(length = 1000)
    var clientAuthenticationMethods: String? = null,

    @Column(length = 1000)
    var authorizationGrantTypes: String? = null,

    @Column(length = 1000)
    var redirectUris: String? = null,

    @Column(length = 1000)
    var postLogoutRedirectUris: String? = null,

    @Column(length = 1000)
    var scopes: String? = null,

    @Column(length = 2000)
    var clientSettings: String? = null,

    @Column(length = 2000)
    var tokenSettings: String? = null,
) {

    companion object {

        private val objectMapper = JacksonUtils.objectMapper(Client::class.java.classLoader)

        fun toObject(client: Client): RegisteredClient {
            val clientAuthenticationMethods: Set<String> = StringUtils.commaDelimitedListToSet(
                client.clientAuthenticationMethods
            )
            val authorizationGrantTypes: Set<String> = StringUtils.commaDelimitedListToSet(
                client.authorizationGrantTypes
            )
            val redirectUris: Set<String?> = StringUtils.commaDelimitedListToSet(
                client.redirectUris
            )
            val postLogoutRedirectUris: Set<String?> = StringUtils.commaDelimitedListToSet(
                client.postLogoutRedirectUris
            )
            val clientScopes: Set<String?> = StringUtils.commaDelimitedListToSet(
                client.scopes
            )

            val builder = RegisteredClient.withId(client.id)
                .clientId(client.clientId)
                .clientIdIssuedAt(client.clientIdIssuedAt)
                .clientSecret(client.clientSecret)
                .clientSecretExpiresAt(client.clientSecretExpiresAt)
                .clientName(client.clientName)
                .clientAuthenticationMethods { authenticationMethods: MutableSet<ClientAuthenticationMethod?> ->
                    clientAuthenticationMethods.forEach { authenticationMethod: String ->
                        authenticationMethods.add(resolveClientAuthenticationMethod(authenticationMethod))
                    }
                }
                .authorizationGrantTypes { grantTypes: MutableSet<AuthorizationGrantType?> ->
                    authorizationGrantTypes.forEach { grantType: String ->
                        grantTypes.add(resolveAuthorizationGrantType(grantType))
                    }
                }
                .redirectUris { uris: MutableSet<String?> ->
                    uris.addAll(redirectUris)
                }
                .postLogoutRedirectUris { uris: MutableSet<String?> ->
                    uris.addAll(postLogoutRedirectUris)
                }
                .scopes { scopes: MutableSet<String?> ->
                    scopes.addAll(clientScopes)
                }

            val clientSettingsMap = objectMapper.parseMap(client.clientSettings!!)
            builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build())

            val tokenSettingsMap = objectMapper.parseMap(client.tokenSettings!!)
            builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build())

            return builder.build()
        }

        fun toEntity(registeredClient: RegisteredClient): Client {
            val clientAuthenticationMethods = registeredClient.clientAuthenticationMethods.map { it.value }
            val authorizationGrantTypes = registeredClient.authorizationGrantTypes.map { it.value }


            val entity = Client()
            entity.id = registeredClient.id
            entity.clientId = registeredClient.clientId
            entity.clientIdIssuedAt = registeredClient.clientIdIssuedAt
            entity.clientSecret = registeredClient.clientSecret
            entity.clientSecretExpiresAt = registeredClient.clientSecretExpiresAt
            entity.clientName = registeredClient.clientName
            entity.clientAuthenticationMethods =
                StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods)
            entity.authorizationGrantTypes = StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes)
            entity.redirectUris = StringUtils.collectionToCommaDelimitedString(registeredClient.redirectUris)
            entity.postLogoutRedirectUris =
                StringUtils.collectionToCommaDelimitedString(registeredClient.postLogoutRedirectUris)
            entity.scopes = StringUtils.collectionToCommaDelimitedString(registeredClient.scopes)

            entity.clientSettings = objectMapper.writeMap(registeredClient.clientSettings.settings)
            entity.tokenSettings = objectMapper.writeMap(registeredClient.tokenSettings.settings)

            return entity
        }

        fun resolveAuthorizationGrantType(authorizationGrantType: String): AuthorizationGrantType {
            if ((AuthorizationGrantType.AUTHORIZATION_CODE.value == authorizationGrantType)) {
                return AuthorizationGrantType.AUTHORIZATION_CODE
            } else if ((AuthorizationGrantType.CLIENT_CREDENTIALS.value == authorizationGrantType)) {
                return AuthorizationGrantType.CLIENT_CREDENTIALS
            } else if ((AuthorizationGrantType.REFRESH_TOKEN.value == authorizationGrantType)) {
                return AuthorizationGrantType.REFRESH_TOKEN
            } else if ((AuthorizationGrantType.DEVICE_CODE.value == authorizationGrantType)) {
                return AuthorizationGrantType.DEVICE_CODE
            }
            return AuthorizationGrantType(authorizationGrantType) // Custom authorization grant type
        }

        fun resolveClientAuthenticationMethod(clientAuthenticationMethod: String): ClientAuthenticationMethod {
            if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value == clientAuthenticationMethod) {
                return ClientAuthenticationMethod.CLIENT_SECRET_BASIC
            } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.value == clientAuthenticationMethod) {
                return ClientAuthenticationMethod.CLIENT_SECRET_POST
            } else if (ClientAuthenticationMethod.NONE.value == clientAuthenticationMethod) {
                return ClientAuthenticationMethod.NONE
            }
            return ClientAuthenticationMethod(clientAuthenticationMethod) // Custom client authentication method
        }
    }
}