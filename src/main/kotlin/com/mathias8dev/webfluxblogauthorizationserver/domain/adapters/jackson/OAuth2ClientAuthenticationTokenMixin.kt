package com.mathias8dev.webfluxblogauthorizationserver.domain.adapters.jackson

import com.fasterxml.jackson.annotation.*
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.*
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.CustomUserDetails
import com.mathias8dev.webfluxblogauthorizationserver.models.Client
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import java.io.IOException


@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonDeserialize(using = OAuth2ClientAuthenticationTokenDeserializer::class)
@JsonAutoDetect(
    fieldVisibility = JsonAutoDetect.Visibility.ANY,
    getterVisibility = JsonAutoDetect.Visibility.NONE,
    isGetterVisibility = JsonAutoDetect.Visibility.NONE
)
@JsonIgnoreProperties(ignoreUnknown = true)
abstract class OAuth2ClientAuthenticationTokenMixin


class OAuth2ClientAuthenticationTokenDeserializer : JsonDeserializer<OAuth2ClientAuthenticationToken?>() {


    private val logger = LoggerFactory.getLogger(OAuth2ClientAuthenticationTokenDeserializer::class.java)

    @Throws(IOException::class)
    override fun deserialize(
        jsonParser: JsonParser,
        deserializationContext: DeserializationContext?
    ): OAuth2ClientAuthenticationToken {
        val mapper = jsonParser.codec as ObjectMapper
        val node = mapper.readTree<JsonNode>(jsonParser)
        logger.debug("The node is $node")
        val clientAuthMethodNode = node["clientAuthenticationMethod"]
        val clientAuthMethod = Client.resolveClientAuthenticationMethod(clientAuthMethodNode["value"].asText(null))
        val credentials = node["credentials"].asText()
        val registeredClientNode = node["registeredClient"]
        val registeredClient = mapper.treeToValue(
            registeredClientNode,
            RegisteredClient::class.java
        )
        val detailsNode = node["details"]

        val details = mapper.treeToValue(
            detailsNode,
            CustomUserDetails::class.java
        )

        logger.debug("The details is $details")
        return OAuth2ClientAuthenticationToken(registeredClient, clientAuthMethod, credentials).apply {
            setDetails(details)
        }
    }
}



