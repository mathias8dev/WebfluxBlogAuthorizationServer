package com.mathias8dev.webfluxblogauthorizationserver.domain

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.module.SimpleModule
import com.mathias8dev.webfluxblogauthorizationserver.domain.adapters.jackson.OAuth2ClientAuthenticationTokenMixin
import com.mathias8dev.webfluxblogauthorizationserver.domain.adapters.jackson.RegisteredClientMixin
import com.mathias8dev.webfluxblogauthorizationserver.domain.adapters.jackson.UserDetailsMixin
import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.CustomUserDetails
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.jackson2.CoreJackson2Module
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module


object JacksonUtils {

    fun objectMapper(classLoader: ClassLoader): ObjectMapper {
        val objectMapper = ObjectMapper()
        SecurityJackson2Modules.getModules(classLoader)?.let {
            objectMapper.registerModules(it)
            objectMapper.registerModule(CoreJackson2Module())
            objectMapper.registerModule(OAuth2AuthorizationServerJackson2Module())
            // Create and register a module to handle serializers and deserializers
            val module = SimpleModule()
            module.setMixInAnnotation(RegisteredClient::class.java, RegisteredClientMixin::class.java)
            module.setMixInAnnotation(
                OAuth2ClientAuthenticationToken::class.java,
                OAuth2ClientAuthenticationTokenMixin::class.java,
            )
            module.setMixInAnnotation(CustomUserDetails::class.java, UserDetailsMixin::class.java)
            module.setMixInAnnotation(UserDetails::class.java, UserDetailsMixin::class.java)
            // Register the module with the ObjectMapper
            objectMapper.registerModule(module)
        }

        return objectMapper
    }


    fun ObjectMapper.parseMap(data: String?): Map<String, Any>? {
        return runCatching {
            readValue(data, object : TypeReference<Map<String, Any>?>() {})
        }.getOrElse {
            throw IllegalArgumentException(it.message, it)
        }
    }

    fun ObjectMapper.writeMap(data: Map<String, Any>?): String? {
        return runCatching {
            writeValueAsString(data)
        }.getOrElse {
            throw IllegalArgumentException(it.message, it)
        }
    }
}