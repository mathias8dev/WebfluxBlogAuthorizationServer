package com.mathias8dev.webfluxblogauthorizationserver.repository

import com.mathias8dev.webfluxblogauthorizationserver.models.Client
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.stereotype.Repository
import org.springframework.util.Assert


@Repository
class JpaRegisteredClientRepository(private val clientRepository: ClientRepository) : RegisteredClientRepository {


    private val logger = LoggerFactory.getLogger(JpaRegisteredClientRepository::class.java)


    override fun save(registeredClient: RegisteredClient) {
        clientRepository.save<Client>(Client.toEntity(registeredClient))
    }

    override fun findById(id: String): RegisteredClient? {
        Assert.hasText(id, "id cannot be empty")
        return clientRepository.findById(id).map { client: Client -> Client.toObject(client) }.orElse(null)
    }

    override fun findByClientId(clientId: String): RegisteredClient? {
        Assert.hasText(clientId, "clientId cannot be empty")
        return clientRepository.findByClientId(clientId).map { client: Client -> Client.toObject(client) }.orElse(null)
    }

}