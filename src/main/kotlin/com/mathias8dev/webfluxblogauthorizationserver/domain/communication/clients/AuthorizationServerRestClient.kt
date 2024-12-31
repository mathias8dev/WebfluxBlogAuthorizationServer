package com.mathias8dev.webfluxblogauthorizationserver.domain.communication.clients

import com.google.gson.JsonObject
import retrofit2.http.Field
import retrofit2.http.FormUrlEncoded
import retrofit2.http.POST

interface AuthorizationServerRestClient {

    @FormUrlEncoded
    @POST("authorization-server/oauth2/token")
    suspend fun accessToken(
        @Field("scope") scope: String = "user.full_read",
        @Field("grant_type") grantType: String = "client_credentials"
    ): JsonObject
}