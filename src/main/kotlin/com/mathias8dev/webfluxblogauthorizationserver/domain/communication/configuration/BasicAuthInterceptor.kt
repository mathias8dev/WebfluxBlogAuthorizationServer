package com.mathias8dev.webfluxblogauthorizationserver.domain.communication.configuration

import okhttp3.Credentials
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import org.slf4j.LoggerFactory
import java.io.IOException


class BasicAuthInterceptor : Interceptor {

    private val logger = LoggerFactory.getLogger(this.javaClass)

    private val clientId = "webfluxblog-oauth2-client"
    private val clientSecret = "webfluxblog-oauth2-client-secret"

    private val credentials: String = Credentials.basic(clientId, clientSecret)

    @Throws(IOException::class)
    override fun intercept(chain: Interceptor.Chain): Response {
        val request: Request = chain.request()
        logger.debug("The request is {}", request)
        val authenticatedRequest: Request = request.newBuilder()
            .header("Authorization", credentials).build()
        return chain.proceed(authenticatedRequest)
    }
}