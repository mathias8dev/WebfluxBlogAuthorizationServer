package com.mathias8dev.webfluxblogauthorizationserver.data.models

data class Role(
    var id: Int = 0,
    var authorities: MutableSet<Authority> = mutableSetOf(),
    var name: String
)
