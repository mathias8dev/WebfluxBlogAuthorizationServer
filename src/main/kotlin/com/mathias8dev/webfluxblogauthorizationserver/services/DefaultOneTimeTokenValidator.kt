package com.mathias8dev.webfluxblogauthorizationserver.services

import com.mathias8dev.webfluxblogauthorizationserver.data.models.User
import com.mathias8dev.webfluxblogauthorizationserver.domain.communication.clients.AuthenticationServerRestClient
import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.CustomUserDetails
import com.mathias8dev.webfluxblogauthorizationserver.domain.utils.toRequestBody
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service


@Service
class DefaultOneTimeTokenValidator(
    private val authenticationServerRestClient: AuthenticationServerRestClient
) : OneTimeTokenValidator {

    private val logger = LoggerFactory.getLogger(javaClass)

    override fun validateOttAndGetUser(username: String, ott: String): UserDetails {
        val user: User = runBlocking {
            kotlin.runCatching {
                authenticationServerRestClient.validateOttAndGetUser(username.toRequestBody(), ott.toRequestBody())
            }.getOrElse {
                logger.debug("An error occurred when trying to validate the ott and retrieve the user")
                it.printStackTrace()
                throw it
            }
        }

        return CustomUserDetails(user)
    }
}

interface OneTimeTokenValidator {
    fun validateOttAndGetUser(username: String, ott: String): UserDetails
}