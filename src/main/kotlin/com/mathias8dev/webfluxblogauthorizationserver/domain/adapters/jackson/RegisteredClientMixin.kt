package com.mathias8dev.webfluxblogauthorizationserver.domain.adapters.jackson

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.*
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer
import com.fasterxml.jackson.databind.jsontype.TypeSerializer
import com.fasterxml.jackson.databind.node.ObjectNode
import com.mathias8dev.webfluxblogauthorizationserver.models.Client
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient


@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
@JsonDeserialize(using = RegisteredClientDeserializer::class)
@JsonSerialize(using = RegisteredClientSerializer::class)
@JsonAutoDetect(
    fieldVisibility = JsonAutoDetect.Visibility.ANY,
    getterVisibility = JsonAutoDetect.Visibility.NONE,
    isGetterVisibility = JsonAutoDetect.Visibility.NONE
)
@JsonIgnoreProperties(ignoreUnknown = true)
abstract class RegisteredClientMixin


class RegisteredClientDeserializer : JsonDeserializer<RegisteredClient?>() {


    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): RegisteredClient {
        val objectMapper = p.codec as ObjectMapper
        val node: JsonNode = objectMapper.readTree(p)

        // Extract type information
        val className = node.get("@class").asText()
        val clientClass = Class.forName(className)

        // Deserialize the data node
        val dataNode = node.get("data")
        val clientEntity = objectMapper.treeToValue(dataNode, Client::class.java)

        return Client.toObject(clientEntity)
    }

    override fun deserializeWithType(
        p: JsonParser,
        ctxt: DeserializationContext,
        typeDeserializer: TypeDeserializer
    ): RegisteredClient {
        return deserialize(p, ctxt)
    }


}


class RegisteredClientSerializer : JsonSerializer<RegisteredClient>() {
    override fun serialize(
        registeredClient: RegisteredClient?,
        jsonGenerator: JsonGenerator,
        serializers: SerializerProvider?
    ) {
        if (registeredClient == null) {
            jsonGenerator.writeNull()
            return
        }

        // Create an object node to represent the serialized data
        val objectMapper = jsonGenerator.codec as ObjectMapper
        val clientNode: ObjectNode = objectMapper.createObjectNode()
        // Add type information
        clientNode.put("@class", registeredClient::class.java.name)

        // Serialize the RegisteredClient object
        val clientEntity = Client.toEntity(registeredClient)
        val clientJson = objectMapper.valueToTree<ObjectNode>(clientEntity)
        clientNode.put("data", clientJson)
        objectMapper.writeTree(jsonGenerator, clientNode)

    }

    override fun serializeWithType(
        registeredClient: RegisteredClient?,
        jsonGenerator: JsonGenerator,
        serializers: SerializerProvider?,
        typeSer: TypeSerializer?
    ) {
        serialize(registeredClient, jsonGenerator, serializers)
    }

}



