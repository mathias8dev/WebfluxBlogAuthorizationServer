package com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.mathias8dev.webfluxblogauthorizationserver.data.models.Ott
import com.mathias8dev.webfluxblogauthorizationserver.data.models.User
import com.mathias8dev.webfluxblogauthorizationserver.domain.adapters.jackson.UserDetailsDeserializer
import com.mathias8dev.webfluxblogauthorizationserver.domain.adapters.jackson.UserDetailsSerializer
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.util.stream.Collectors


@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
@JsonSerialize(using = UserDetailsSerializer::class)
@JsonDeserialize(using = UserDetailsDeserializer::class)
class CustomUserDetails : UserDetails {
    private var password: String? = null
    var oneTimeToken: Ott? = null
        private set
    private val username: String
    private val active: Boolean
    private val accountNonExpired: Boolean
    private val accountNonLocked: Boolean
    private val credentialsNonExpired: Boolean
    private val authorities: Collection<GrantedAuthority>?

    @JsonCreator
    constructor(
        username: String,
        authorities: Collection<GrantedAuthority>?,
        active: Boolean = true,
        accountNonExpired: Boolean = true,
        credentialsNonExpired: Boolean = true,
        accountNonLocked: Boolean = true
    ) {
        this.username = username
        this.authorities = authorities
        this.active = active
        this.credentialsNonExpired = credentialsNonExpired
        this.accountNonExpired = accountNonExpired
        this.accountNonLocked = accountNonLocked
    }

    @JsonCreator
    constructor(
        username: String,
        password: String?,
        oneTimeToken: Ott?,
        authorities: Collection<String>?,
        active: Boolean = true,
        accountNonExpired: Boolean = true,
        credentialsNonExpired: Boolean = true,
        accountNonLocked: Boolean = true
    ) {
        this.username = username
        this.password = password
        this.oneTimeToken = oneTimeToken
        this.active = active
        this.credentialsNonExpired = credentialsNonExpired
        this.accountNonExpired = accountNonExpired
        this.accountNonLocked = accountNonLocked
        this.authorities = authorities?.stream()
            ?.map { authority: String? ->
                SimpleGrantedAuthority(
                    authority
                )
            }?.collect(Collectors.toSet())
    }


    constructor(user: User) {
        this.username = user.username
        this.password = user.password
        this.oneTimeToken = user.oneTimeToken
        this.active = user.active
        this.credentialsNonExpired = user.credentialsNonExpired
        this.accountNonExpired = user.accountNonExpired
        this.accountNonLocked = user.accountNonLocked
        this.authorities = mutableSetOf<GrantedAuthority>().apply {
            user.roles.forEach {
                val role = if (it.name.startsWith("ROLE_")) it.name else "ROLE_${it.name}"
                val authorities = it.authorities.map { authority ->
                    SimpleGrantedAuthority(authority.name)
                }

                add(SimpleGrantedAuthority(role))
                addAll(authorities)

            }
        }
    }

    override fun getAuthorities(): Collection<GrantedAuthority>? {
        return authorities
    }

    override fun getPassword(): String? {
        return password
    }

    override fun getUsername(): String {
        return this.username
    }

    override fun isAccountNonExpired(): Boolean {
        return accountNonLocked
    }

    override fun isAccountNonLocked(): Boolean {
        return accountNonLocked
    }

    override fun isCredentialsNonExpired(): Boolean {
        return credentialsNonExpired
    }

    override fun isEnabled(): Boolean {
        return active
    }
}