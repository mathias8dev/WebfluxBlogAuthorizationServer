package com.mathias8dev.webfluxblogauthorizationserver.data.models

import java.time.LocalDateTime

interface HasTimestamp {
    var createdAt: LocalDateTime
    var updatedAt: LocalDateTime
}