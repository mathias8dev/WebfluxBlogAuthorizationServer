package com.mathias8dev.webfluxblogauthorizationserver.loader

import com.mathias8dev.webfluxblogauthorizationserver.domain.annotations.Populator
import com.mathias8dev.webfluxblogauthorizationserver.domain.configuration.security.customGrant.grantPassword.AuthorizationGrantTypePassword
import com.mathias8dev.webfluxblogauthorizationserver.repository.JpaRegisteredClientRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import java.time.Duration
import java.util.*


@Populator
class ClientDataLoader(
    private val clientRepository: JpaRegisteredClientRepository
) : DataPopulator {

    override fun populate() {
        val oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("oidc-client")
            .clientSecret("{bcrypt}\$2y\$10\$Q4zhUxx9bz.VNDclM0yLQumaRBLii6txjACDkqcWOnzc2PyCbgo6q")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantTypePassword.GRANT_PASSWORD)
            .redirectUri("http://localhost:8080/auth")
            .postLogoutRedirectUri("http://localhost:8080/")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope("client.create")
            .scope("client.read")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .tokenSettings(
                TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                    .accessTokenTimeToLive(Duration.ofMinutes(30))
                    .refreshTokenTimeToLive(Duration.ofDays(90))
                    .authorizationCodeTimeToLive(Duration.ofMinutes(2))
                    .reuseRefreshTokens(false)
                    .build()
            )
            .build()


        val webfluxblogAppClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("webfluxblog-app-client")
            .clientSecret("{bcrypt}\$2y\$10\$snzoIyV/DQfg5741LqUa9OjciGWgPMIsOqKqykJcxdKzdpsKrikgi")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantTypePassword.GRANT_PASSWORD)
            .redirectUri("http://localhost:8080/auth")
            .postLogoutRedirectUri("http://localhost:8080/")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope("user.full_read")
            .scope("user.create")
            .scope("user.read")
            .scope("data.read")
            .scope("webfluxblog.app")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .tokenSettings(
                TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                    .accessTokenTimeToLive(Duration.ofMinutes(30))
                    .refreshTokenTimeToLive(Duration.ofDays(90))
                    .authorizationCodeTimeToLive(Duration.ofMinutes(2))
                    .reuseRefreshTokens(false)
                    .build()
            )
            .build()

        val webfluxblogAdminClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("webfluxblog-admin-client")
            .clientSecret("{bcrypt}\$2y\$10\$97hShczzRRM1ARESyxIjceaX6AO/ydFDAnEZXgo4anoLXDUZWJp42")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantTypePassword.GRANT_PASSWORD)
            .redirectUri("http://localhost:8080/auth")
            .postLogoutRedirectUri("http://localhost:8080/")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope("user.full_read")
            .scope("user.create")
            .scope("user.read")
            .scope("data.read")
            .scope("webfluxblog.admin")
            .scope("client.create")
            .scope("client.read")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .tokenSettings(
                TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                    .accessTokenTimeToLive(Duration.ofMinutes(30))
                    .refreshTokenTimeToLive(Duration.ofDays(90))
                    .authorizationCodeTimeToLive(Duration.ofMinutes(2))
                    .reuseRefreshTokens(false)
                    .build()
            )
            .build()

        val webfluxblogOAuth2Client = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("webfluxblog-oauth2-client")
            .clientSecret("{bcrypt}\$2y\$10\$9dAYUmlryS9SykIOd9Mp..ArgCuk6w4fKkmxhEkFfDw09FBs5o5TG")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantTypePassword.GRANT_PASSWORD)
            .redirectUri("http://localhost:8080/auth")
            .postLogoutRedirectUri("http://localhost:8080/")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope("user.full_read")
            .scope("data.read")
            .scope("user.create")
            .scope("notify")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .tokenSettings(
                TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                    .accessTokenTimeToLive(Duration.ofMinutes(30))
                    .refreshTokenTimeToLive(Duration.ofDays(90))
                    .authorizationCodeTimeToLive(Duration.ofMinutes(2))
                    .reuseRefreshTokens(false)
                    .build()
            )
            .build()

        clientRepository.save(oidcClient)
        clientRepository.save(webfluxblogAppClient)
        clientRepository.save(webfluxblogAdminClient)
        clientRepository.save(webfluxblogOAuth2Client)
    }
}
