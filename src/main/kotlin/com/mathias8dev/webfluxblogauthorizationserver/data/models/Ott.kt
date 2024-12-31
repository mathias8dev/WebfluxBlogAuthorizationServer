package com.mathias8dev.webfluxblogauthorizationserver.data.models

import java.time.Instant
import java.time.LocalDateTime

data class Ott(
    var id: Long = 0,
    var token: String,
    var expiresAt: Instant,
    var used: Boolean = false,
    var usedAt: Instant? = null,
    var createdAt: LocalDateTime? = null,
)