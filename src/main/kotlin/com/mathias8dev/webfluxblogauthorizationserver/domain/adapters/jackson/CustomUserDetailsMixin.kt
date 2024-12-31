package com.mathias8dev.webfluxblogauthorizationserver.domain.adapters.jackson

import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.*
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer
import com.fasterxml.jackson.databind.jsontype.TypeSerializer
import com.mathias8dev.webfluxblogauthorizationserver.data.models.Ott
import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.CustomUserDetails
import com.mathias8dev.webfluxblogauthorizationserver.domain.utils.toJson
import com.mathias8dev.webfluxblogauthorizationserver.domain.utils.toTypedData
import org.springframework.security.core.userdetails.UserDetails

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
@JsonDeserialize(using = UserDetailsDeserializer::class)
@JsonSerialize(using = UserDetailsSerializer::class)
abstract class UserDetailsMixin

class UserDetailsDeserializer : JsonDeserializer<UserDetails>() {

    override fun deserialize(parser: JsonParser, ctxt: DeserializationContext): UserDetails {
        val objectMapper = parser.codec as ObjectMapper
        val node: JsonNode = objectMapper.readTree(parser)

        // Extract type information
        val username = node.get("username").asText()
        val password = node.get("password").asText()
        val enabled = node.get("enabled").asBoolean()
        val accountNonExpired = node.get("accountNonExpired").asBoolean()
        val accountNonLocked = node.get("accountNonLocked").asBoolean()
        val credentialsNonExpired = node.get("credentialsNonExpired").asBoolean()
        val authoritiesNode = node.get("authorities")
        val oneTimeToken = node.get("oneTimeToken").asText().toTypedData<Ott?>()

        val authorities = authoritiesNode.map { it.textValue() }


        return CustomUserDetails(
            username,
            password,
            oneTimeToken,
            authorities,
            enabled,
            accountNonExpired,
            credentialsNonExpired,
            accountNonLocked
        )
    }

    override fun deserializeWithType(
        p: JsonParser,
        ctxt: DeserializationContext,
        typeDeserializer: TypeDeserializer
    ): UserDetails {
        return deserialize(p, ctxt)
    }
}


class UserDetailsSerializer : JsonSerializer<UserDetails>() {
    override fun serialize(
        value: UserDetails?,
        jsonGenerator: JsonGenerator,
        provider: SerializerProvider?
    ) {
        if (value == null) {
            jsonGenerator.writeNull()
            return
        }

        jsonGenerator.writeStartObject()
        jsonGenerator.writeStringField("@class", value.javaClass.name)
        jsonGenerator.writeStringField("username", value.username)
        jsonGenerator.writeStringField("password", value.password)
        jsonGenerator.writeArrayFieldStart("authorities")
        value.authorities.forEach { jsonGenerator.writeString(it.authority) }
        jsonGenerator.writeEndArray()

        jsonGenerator.writeBooleanField("enabled", value.isEnabled) // Assuming these fields are always true
        jsonGenerator.writeBooleanField("accountNonExpired", value.isAccountNonExpired)
        jsonGenerator.writeBooleanField("accountNonLocked", value.isAccountNonLocked)
        jsonGenerator.writeBooleanField("credentialsNonExpired", value.isCredentialsNonExpired)
        jsonGenerator.writeStringField("oneTimeToken", (value as? CustomUserDetails)?.oneTimeToken?.toJson())
        jsonGenerator.writeEndObject()
    }

    override fun serializeWithType(
        value: UserDetails?,
        jsonGenerator: JsonGenerator,
        serializers: SerializerProvider?,
        typeSer: TypeSerializer?
    ) {
        serialize(value, jsonGenerator, serializers)
    }
}