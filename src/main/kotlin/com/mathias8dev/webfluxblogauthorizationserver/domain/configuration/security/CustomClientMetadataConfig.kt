package com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security

import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientConfigurationAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.oidc.converter.OidcClientRegistrationRegisteredClientConverter
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.util.CollectionUtils
import java.util.function.Consumer
import java.util.function.Function
import java.util.stream.Collectors

class CustomClientMetadataConfig {

    companion object {
        fun configureCustomClientMetadataConverters(): Consumer<List<AuthenticationProvider>> {
            val customClientMetadata = listOf("logo_uri", "contacts")

            return Consumer<List<AuthenticationProvider>> { authenticationProviders: List<AuthenticationProvider> ->
                val registeredClientConverter = CustomRegisteredClientConverter(customClientMetadata)
                val clientRegistrationConverter = CustomClientRegistrationConverter(customClientMetadata)

                authenticationProviders.forEach { authenticationProvider ->
                    if (authenticationProvider is OidcClientRegistrationAuthenticationProvider) {
                        authenticationProvider.setRegisteredClientConverter(registeredClientConverter)
                        authenticationProvider.setClientRegistrationConverter(clientRegistrationConverter)
                    }
                    if (authenticationProvider is OidcClientConfigurationAuthenticationProvider) {
                        authenticationProvider.setClientRegistrationConverter(clientRegistrationConverter)
                    }
                }
            }
        }

        private class CustomRegisteredClientConverter(
            private val customClientMetadata: List<String>
        ) : Converter<OidcClientRegistration, RegisteredClient> {

            private val delegate: OidcClientRegistrationRegisteredClientConverter =
                OidcClientRegistrationRegisteredClientConverter()


            override fun convert(clientRegistration: OidcClientRegistration): RegisteredClient {
                val registeredClient = this.delegate.convert(clientRegistration)
                val clientSettingsBuilder = ClientSettings.withSettings(
                    registeredClient?.clientSettings?.settings ?: emptyMap()
                )
                if (!CollectionUtils.isEmpty(this.customClientMetadata)) {
                    clientRegistration.claims.forEach { (claim, value) ->
                        if (this.customClientMetadata.contains(claim)) {
                            clientSettingsBuilder.setting(claim, value)
                        }
                    }
                }

                return RegisteredClient.from(registeredClient)
                    .clientSettings(clientSettingsBuilder.build())
                    .build()
            }

        }
    }

    private class CustomClientRegistrationConverter(
        private val customClientMetadata: List<String>
    ) : Converter<RegisteredClient, OidcClientRegistration> {

        private val delegate: RegisteredClientOidcClientRegistrationConverter =
            RegisteredClientOidcClientRegistrationConverter()

        override fun convert(registeredClient: RegisteredClient): OidcClientRegistration {
            val clientRegistration = this.delegate.convert(registeredClient)
            val claims = clientRegistration?.claims?.toMutableMap() ?: mutableMapOf()
            if (!CollectionUtils.isEmpty(this.customClientMetadata)) {
                val clientSettings = registeredClient.clientSettings
                claims.putAll(this.customClientMetadata.stream()
                    .filter { metadata -> clientSettings.getSetting<Any?>(metadata) != null }
                    .collect(Collectors.toMap(Function.identity(), clientSettings::getSetting)))
            }

            return OidcClientRegistration.withClaims(claims).build()
        }

    }

}