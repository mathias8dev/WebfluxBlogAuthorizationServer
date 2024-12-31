package com.mathias8dev.webfluxblogauthorizationserver.services

import com.mathias8dev.webfluxblogauthorizationserver.models.AuthorizationConsent
import com.mathias8dev.webfluxblogauthorizationserver.repository.AuthorizationConsentRepository
import org.springframework.dao.DataRetrievalFailureException
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.stereotype.Service
import org.springframework.util.Assert


@Service
class JpaOAuth2AuthorizationConsentService(
    private val authorizationConsentRepository: AuthorizationConsentRepository,
    private val registeredClientRepository: RegisteredClientRepository
) : OAuth2AuthorizationConsentService {


    override fun save(authorizationConsent: OAuth2AuthorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null")
        authorizationConsentRepository.save(AuthorizationConsent.toEntity(authorizationConsent))
    }

    override fun remove(authorizationConsent: OAuth2AuthorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null")
        authorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
            authorizationConsent.registeredClientId, authorizationConsent.principalName
        )
    }

    override fun findById(registeredClientId: String, principalName: String): OAuth2AuthorizationConsent? {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty")
        Assert.hasText(principalName, "principalName cannot be empty")
        return authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(
            registeredClientId, principalName
        ).map { authorizationConsent: AuthorizationConsent ->
            AuthorizationConsent.toObject(
                authorizationConsent,
                getRegisteredClient(authorizationConsent)

            )
        }.orElse(null)
    }

    fun getRegisteredClient(authorizationConsent: AuthorizationConsent): RegisteredClient {
        return registeredClientRepository.findById(authorizationConsent.registeredClientId)
            ?: throw DataRetrievalFailureException(
                "The RegisteredClient with id '${authorizationConsent.registeredClientId}' was not found in the RegisteredClientRepository."
            )
    }
}