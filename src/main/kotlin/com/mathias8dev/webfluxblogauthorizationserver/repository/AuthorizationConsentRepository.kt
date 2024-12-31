package com.mathias8dev.webfluxblogauthorizationserver.repository

import com.mathias8dev.webfluxblogauthorizationserver.models.AuthorizationConsent
import com.mathias8dev.webfluxblogauthorizationserver.models.AuthorizationConsent.AuthorizationConsentId
import org.springframework.data.jpa.repository.JpaRepository
import java.util.*


interface AuthorizationConsentRepository : JpaRepository<AuthorizationConsent, AuthorizationConsentId> {
    fun findByRegisteredClientIdAndPrincipalName(
        registeredClientId: String,
        principalName: String
    ): Optional<AuthorizationConsent>

    fun deleteByRegisteredClientIdAndPrincipalName(registeredClientId: String, principalName: String)
}