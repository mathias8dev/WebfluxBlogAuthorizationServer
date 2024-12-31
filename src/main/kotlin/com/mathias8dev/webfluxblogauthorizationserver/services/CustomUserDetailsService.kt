package com.mathias8dev.webfluxblogauthorizationserver.services

import com.mathias8dev.webfluxblogauthorizationserver.data.models.User
import com.mathias8dev.webfluxblogauthorizationserver.domain.communication.clients.AuthenticationServerRestClient
import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.CustomUserDetails
import com.mathias8dev.webfluxblogauthorizationserver.domain.utils.toRequestBody
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class CustomUserDetailsService(
    private val authenticationServerRestClient: AuthenticationServerRestClient,
) : UserDetailsService {

    private val logger = LoggerFactory.getLogger(CustomUserDetailsService::class.java)

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String): UserDetails {
        val user: User = runBlocking {
            kotlin.runCatching { authenticationServerRestClient.findByUsername(username.toRequestBody()) }.getOrElse {
                logger.debug("An error occurred when trying to retrieve on the authentication server the user by its username")
                it.printStackTrace()
                throw UsernameNotFoundException("Unable to find user: $username")
            }
        }

        return CustomUserDetails(user)
    }


}

