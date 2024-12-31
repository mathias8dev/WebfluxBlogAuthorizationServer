package com.mathias8dev.webfluxblogauthorizationserver.repository

import com.mathias8dev.webfluxblogauthorizationserver.models.Client
import org.springframework.data.jpa.repository.JpaRepository
import java.util.*


interface ClientRepository : JpaRepository<Client, String> {
    fun findByClientId(clientId: String): Optional<Client>
}