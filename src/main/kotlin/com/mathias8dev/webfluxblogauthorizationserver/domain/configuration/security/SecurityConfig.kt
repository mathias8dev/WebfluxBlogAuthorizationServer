package com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security

import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantOtt.GrantOttAuthenticationProvider
import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantOtt.OAuth2GrantOttAuthenticationConverter
import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantPassword.GrantPasswordAuthenticationProvider
import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantPassword.OAuth2GrantPasswordAuthenticationConverter
import com.mathias8dev.webfluxblogauthorizationserver.services.OneTimeTokenValidator
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.core.env.Environment
import org.springframework.core.env.get
import org.springframework.http.MediaType
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.*
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


@Configuration
@EnableWebSecurity
class SecurityConfig {
    @Bean
    @Order(1)
    @Throws(Exception::class)
    fun authorizationServerSecurityFilterChain(
        http: HttpSecurity,
        tokenGenerator: OAuth2TokenGenerator<*>,
        grantPasswordAuthenticationProvider: GrantPasswordAuthenticationProvider,
        grantOttAuthenticationProvider: GrantOttAuthenticationProvider,
        daoAuthenticationProvider: DaoAuthenticationProvider,
        refreshTokenAuthenticationProvider: OAuth2RefreshTokenAuthenticationProvider,
    ): SecurityFilterChain {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
            .tokenGenerator(tokenGenerator)
            .tokenEndpoint { tokenEndpoint ->
                tokenEndpoint
                    .accessTokenRequestConverter(OAuth2GrantPasswordAuthenticationConverter())
                    .accessTokenRequestConverter(OAuth2GrantOttAuthenticationConverter())
                    .authenticationProvider(grantPasswordAuthenticationProvider)
                    .authenticationProvider(grantOttAuthenticationProvider)
                    .authenticationProvider(daoAuthenticationProvider)
            }
            .oidc {
                it.userInfoEndpoint { configurer ->
                    configurer.userInfoMapper { context ->
                        val authentication: OidcUserInfoAuthenticationToken = context.getAuthentication()
                        val principal = authentication.principal as JwtAuthenticationToken
                        OidcUserInfo(principal.token.claims)
                    }
                }.clientRegistrationEndpoint { endpoint ->
                    endpoint.authenticationProviders(CustomClientMetadataConfig.configureCustomClientMetadataConverters())
                }
            } // Enable OpenID Connect 1.0
        http // Redirect to the login page when not authenticated from the
            // authorization endpoint
            .exceptionHandling { exceptions: ExceptionHandlingConfigurer<HttpSecurity?> ->
                exceptions
                    .defaultAuthenticationEntryPointFor(
                        LoginUrlAuthenticationEntryPoint("/login"),
                        MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                    )
            } // Accept access tokens for User Info and/or Client Registration
            .oauth2ResourceServer { resourceServer: OAuth2ResourceServerConfigurer<HttpSecurity?> ->
                resourceServer
                    .jwt(Customizer.withDefaults())
            }


        return http.build()
    }


    @Bean
    @Order(2)
    @Throws(Exception::class)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorize ->
                authorize
                    .anyRequest().authenticated()
            } // Form login handles the redirect to the login page from the
            // authorization server filter chain
            .formLogin(Customizer.withDefaults())

        return http.build()
    }

    @Bean
    fun daoAuthenticationProvider(
        passwordEncoder: PasswordEncoder?, userDetailsService: UserDetailsService?
    ): DaoAuthenticationProvider {
        val daoAuthenticationProvider = DaoAuthenticationProvider()
        daoAuthenticationProvider.setUserDetailsService(userDetailsService)
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder)
        return daoAuthenticationProvider
    }

    @Bean
    fun grantPasswordAuthenticationProvider(
        userDetailsService: UserDetailsService,
        tokenGenerator: OAuth2TokenGenerator<*>,
        authorizationService: OAuth2AuthorizationService,
        passwordEncoder: PasswordEncoder
    ): GrantPasswordAuthenticationProvider {
        return GrantPasswordAuthenticationProvider(
            authorizationService, tokenGenerator, userDetailsService, passwordEncoder
        )
    }

    @Bean
    fun grantOttAuthenticationProvider(
        oneTimeTokenValidator: OneTimeTokenValidator,
        tokenGenerator: OAuth2TokenGenerator<*>,
        authorizationService: OAuth2AuthorizationService,
        passwordEncoder: PasswordEncoder
    ): GrantOttAuthenticationProvider {
        return GrantOttAuthenticationProvider(
            authorizationService,
            tokenGenerator,
            oneTimeTokenValidator,
            passwordEncoder
        )
    }

    @Bean
    fun refreshTokenAuthenticationProvider(
        authorizationService: OAuth2AuthorizationService,
        tokenGenerator: OAuth2TokenGenerator<*>,
    ): OAuth2RefreshTokenAuthenticationProvider {
        val refreshTokenAuthenticationProvider =
            OAuth2RefreshTokenAuthenticationProvider(authorizationService, tokenGenerator)
        return refreshTokenAuthenticationProvider
    }


    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder()
    }

    @Bean
    fun authorizationServerSettings(
        environment: Environment
    ): AuthorizationServerSettings {
        val builder = AuthorizationServerSettings.builder()
        environment["webfluxblog.security.jwt.issuer-uri"]?.let { issuerUri ->
            builder.issuer(issuerUri)
        }
        return builder.build()
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair = generateRsaKey()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        val rsaKey: RSAKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet(jwkSet)
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>?): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }


    @Bean
    fun jwtEncoder(jwkSource: JWKSource<SecurityContext?>?): JwtEncoder {
        return NimbusJwtEncoder(jwkSource)
    }


    @Bean
    fun tokenGenerator(
        jwtEncoder: JwtEncoder,
        jwtTokenCustomizer: OAuth2TokenCustomizer<JwtEncodingContext>,
        accessTokenCustomizer: OAuth2TokenCustomizer<OAuth2TokenClaimsContext>,
    ): OAuth2TokenGenerator<out OAuth2Token?> {
        val jwtGenerator = JwtGenerator(jwtEncoder)
        jwtGenerator.setJwtCustomizer(jwtTokenCustomizer)
        val accessTokenGenerator = OAuth2AccessTokenGenerator()
        accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer)
        val refreshTokenGenerator = OAuth2RefreshTokenGenerator()


        return DelegatingOAuth2TokenGenerator(
            jwtGenerator, accessTokenGenerator, refreshTokenGenerator
        )
    }

    @Bean
    fun jwtTokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> {
        return OAuth2TokenCustomizer<JwtEncodingContext> { context: JwtEncodingContext ->
            addUserInfoClaims(context) { providedClaims ->
                context.claims.claims {
                    it.putAll(providedClaims)
                    // Fix for jackson
                    it["aud"] = it["aud"]?.let { aud ->
                        if (aud is Collection<*>) aud.toMutableSet()
                        else aud
                    }
                    it["scope"] = it["scope"]?.let { aud ->
                        if (aud is Collection<*>) aud.toMutableSet()
                        else aud
                    }
                }
            }
        }
    }

    @Bean
    fun accessTokenCustomizer(): OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {
        return OAuth2TokenCustomizer { context: OAuth2TokenClaimsContext ->
            addUserInfoClaims(context) { providedClaims ->
                context.claims.claims {
                    it.putAll(providedClaims)
                    // Fix for jackson
                    it["aud"] = it["aud"]?.let { aud ->
                        if (aud is Collection<*>) aud.toMutableSet()
                        else aud
                    }
                    it["scope"] = it["scope"]?.let { scope ->
                        if (scope is Collection<*>) scope.toMutableSet()
                        else scope
                    }
                }
            }

        }
    }


    companion object {

        private fun generateRsaKey(): KeyPair {
            val keyPair: KeyPair
            try {
                val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
                keyPairGenerator.initialize(2048)
                keyPair = keyPairGenerator.generateKeyPair()
            } catch (ex: java.lang.Exception) {
                throw IllegalStateException(ex)
            }
            return keyPair
        }

        private fun addUserInfoClaims(context: OAuth2TokenContext, claimsConsumer: (List<Pair<String, Any>>) -> Unit) {
            val authentication = context.getPrincipal<Authentication>()
            println("The authentication attributes details is  ${authentication.details}")
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.tokenType) ||
                context.authorizationGrantType == AuthorizationGrantType.CLIENT_CREDENTIALS
            ) return
            val userDetails = if (authentication is OAuth2ClientAuthenticationToken) {
                authentication.details as? UserDetails
            } else if (authentication is AbstractAuthenticationToken) {
                authentication.principal as? UserDetails
            } else {
                throw IllegalStateException("Unexpected token type")
            }

            //check(!userDetails?.username.isNullOrBlank()) { "Bad UserDetails, username is empty" }

            userDetails?.let {
                val authorities = mutableSetOf<String>()
                val roles = mutableSetOf<String>()
                userDetails.authorities?.forEach {
                    if (it.authority.startsWith("ROLE_")) {
                        roles.add(it.authority.replaceFirst("ROLE_", ""))
                    } else {
                        authorities.add(it.authority)
                    }
                }


                claimsConsumer.invoke(
                    listOf(
                        "authorities" to authorities,
                        "roles" to roles,
                        "username" to userDetails.username,
                        "sub" to userDetails.username,
                    )
                )
            }
        }
    }
}