package com.mathias8dev.webfluxblogauthorizationserver.models

import jakarta.persistence.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.util.StringUtils
import java.io.Serializable


@Entity
@Table(name = "authorization_consent")
@IdClass(AuthorizationConsent.AuthorizationConsentId::class)
class AuthorizationConsent(
    @Id
    var registeredClientId: String? = null,

    @Id
    var principalName: String? = null,

    @Column(length = 1000)
    var authorities: String? = null,


    ) {
    data class AuthorizationConsentId(
        var registeredClientId: String? = null,
        var principalName: String? = null,
    ) : Serializable


    companion object {
        fun toObject(
            authorizationConsent: AuthorizationConsent,
            registeredClient: RegisteredClient
        ): OAuth2AuthorizationConsent {
            val registeredClientId = authorizationConsent.registeredClientId

            val builder = OAuth2AuthorizationConsent.withId(
                (registeredClientId)!!, (authorizationConsent.principalName)!!
            )
            if (authorizationConsent.authorities != null) {
                for (authority: String in StringUtils.commaDelimitedListToSet(authorizationConsent.authorities)
                    .toHashSet()) {
                    builder.authority(SimpleGrantedAuthority(authority))
                }
            }

            return builder.build()
        }

        fun toEntity(authorizationConsent: OAuth2AuthorizationConsent): AuthorizationConsent {
            val entity = AuthorizationConsent()
            entity.registeredClientId = authorizationConsent.registeredClientId
            entity.principalName = authorizationConsent.principalName

            val authorities: MutableSet<String> = HashSet()
            for (authority: GrantedAuthority in authorizationConsent.authorities) {
                authorities.add(authority.authority)
            }
            entity.authorities = StringUtils.collectionToCommaDelimitedString(authorities)

            return entity
        }
    }
}