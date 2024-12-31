package com.mathias8dev.webfluxblogauthorizationserver.data.models

import java.time.LocalDateTime

data class User(
    var id: Long,
    val roles: MutableSet<Role> = mutableSetOf(),
    var username: String,
    var password: String,
    var active: Boolean = true,
    var oneTimeToken: Ott? = null,
    var credentialsNonExpired: Boolean = true,
    var accountNonExpired: Boolean = true,
    var accountNonLocked: Boolean = true,
    override var createdAt: LocalDateTime = LocalDateTime.now(),
    override var updatedAt: LocalDateTime = LocalDateTime.now(),
) : HasTimestamp