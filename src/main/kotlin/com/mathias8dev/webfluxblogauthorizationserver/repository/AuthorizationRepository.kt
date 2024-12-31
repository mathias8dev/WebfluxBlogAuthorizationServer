package com.mathias8dev.webfluxblogauthorizationserver.repository

import com.mathias8dev.webfluxblogauthorizationserver.models.Authorization
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.util.*


interface AuthorizationRepository : JpaRepository<Authorization, String> {
    fun findByState(state: String): Optional<Authorization>
    fun findByAuthorizationCodeValue(authorizationCode: String): Optional<Authorization>
    fun findByAccessTokenValue(accessToken: String): Optional<Authorization>
    fun findByRefreshTokenValue(refreshToken: String): Optional<Authorization>
    fun findByOidcIdTokenValue(idToken: String): Optional<Authorization>
    fun findByUserCodeValue(userCode: String): Optional<Authorization>
    fun findByDeviceCodeValue(deviceCode: String): Optional<Authorization>

    @Query(
        "select a from Authorization a where a.state = :token" +
                " or a.authorizationCodeValue = :token" +
                " or a.accessTokenValue = :token" +
                " or a.refreshTokenValue = :token" +
                " or a.oidcIdTokenValue = :token" +
                " or a.userCodeValue = :token" +
                " or a.deviceCodeValue = :token"
    )
    fun findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(
        @Param("token") token: String
    ): Optional<Authorization>
}