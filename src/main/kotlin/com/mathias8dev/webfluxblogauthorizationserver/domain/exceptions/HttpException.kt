package com.mathias8dev.webfluxblogauthorizationserver.domain.exceptions

import org.springframework.http.HttpStatus


data class HttpException(
    val httpStatus: HttpStatus,
    override val message: String?,
    override val cause: Throwable? = null
) : RuntimeException(message, cause)