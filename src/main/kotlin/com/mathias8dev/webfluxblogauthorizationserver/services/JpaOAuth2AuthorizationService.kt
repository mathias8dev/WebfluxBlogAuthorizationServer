package com.mathias8dev.webfluxblogauthorizationserver.services

import com.mathias8dev.webfluxblogauthorizationserver.models.Authorization
import com.mathias8dev.webfluxblogauthorizationserver.repository.AuthorizationRepository
import org.slf4j.LoggerFactory
import org.springframework.dao.DataRetrievalFailureException
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.stereotype.Service
import org.springframework.util.Assert
import java.util.*


@Service
class JpaOAuth2AuthorizationService(
    private val authorizationRepository: AuthorizationRepository,
    private val registeredClientRepository: RegisteredClientRepository
) : OAuth2AuthorizationService {


    private val logger = LoggerFactory.getLogger(JpaOAuth2AuthorizationService::class.java)


    override fun save(authorization: OAuth2Authorization) {
        logger.debug("@@@ save $authorization")
        Assert.notNull(authorization, "authorization cannot be null")
        val data =
            kotlin.runCatching { authorizationRepository.save<Authorization>(Authorization.toEntity(authorization)) }
                .getOrElse {
                    logger.debug("An error occured")
                    it.printStackTrace()
                }

        logger.debug("The data is $data")
    }

    override fun remove(authorization: OAuth2Authorization) {
        Assert.notNull(authorization, "authorization cannot be null")
        authorizationRepository.deleteById(authorization.id)
        logger.debug("@@@ remove $authorization")
    }

    override fun findById(id: String): OAuth2Authorization? {
        Assert.hasText(id, "id cannot be empty")

        return authorizationRepository.findById(id).map { entity: Authorization ->
            Authorization.toObject(
                entity,
                getRegisteredClient(entity)
            )
        }.orElse(null)
        logger.debug("@@@ findById $id")
    }

    fun getRegisteredClient(entity: Authorization): RegisteredClient {
        return registeredClientRepository.findById(entity.registeredClientId)
            ?: throw DataRetrievalFailureException(
                ("The RegisteredClient with id '" + entity.registeredClientId) + "' was not found in the RegisteredClientRepository."
            )
    }

    override fun findByToken(token: String, tokenType: OAuth2TokenType?): OAuth2Authorization? {
        Assert.hasText(token, "token cannot be empty")


        val result: Optional<Authorization> = if (tokenType == null) {

            authorizationRepository.findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(
                token
            )
        } else if ((OAuth2ParameterNames.STATE == tokenType.value)) {
            authorizationRepository.findByState(token)
        } else if ((OAuth2ParameterNames.CODE == tokenType.value)) {
            authorizationRepository.findByAuthorizationCodeValue(token)
        } else if ((OAuth2ParameterNames.ACCESS_TOKEN == tokenType.value)) {
            authorizationRepository.findByAccessTokenValue(token)
        } else if ((OAuth2ParameterNames.REFRESH_TOKEN == tokenType.value)) {
            authorizationRepository.findByRefreshTokenValue(token)
        } else if ((OidcParameterNames.ID_TOKEN == tokenType.value)) {
            authorizationRepository.findByOidcIdTokenValue(token)
        } else if ((OAuth2ParameterNames.USER_CODE == tokenType.value)) {
            authorizationRepository.findByUserCodeValue(token)
        } else if ((OAuth2ParameterNames.DEVICE_CODE == tokenType.value)) {
            authorizationRepository.findByDeviceCodeValue(token)
        } else {
            Optional.empty()
        }
        logger.debug("@@@ findByToken")
        return result.map { entity: Authorization ->
            Authorization.toObject(entity, getRegisteredClient(entity))
        }.orElse(null)
    }

    fun findAll(): List<Authorization> {
        return authorizationRepository.findAll()
    }


}