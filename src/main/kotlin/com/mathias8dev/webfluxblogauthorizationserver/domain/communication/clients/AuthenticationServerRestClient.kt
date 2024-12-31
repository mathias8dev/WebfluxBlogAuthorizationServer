package com.mathias8dev.webfluxblogauthorizationserver.domain.communication.clients


import com.mathias8dev.webfluxblogauthorizationserver.data.models.User
import okhttp3.RequestBody
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part


interface AuthenticationServerRestClient {

    @Multipart
    @POST("authentication-server/find/by/username")
    suspend fun findByUsername(@Part("username") username: RequestBody): User


    @Multipart
    @POST("authentication-server/validate-ott-and-get-user")
    suspend fun validateOttAndGetUser(@Part("username") username: RequestBody, @Part("ott") ott: RequestBody): User

}