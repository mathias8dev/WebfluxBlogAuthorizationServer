package com.mathias8dev.webfluxblogauthorizationserver.domain.communication.configuration

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.mathias8dev.webfluxblogauthorizationserver.domain.adapters.gson.InstantTypeAdapter
import com.mathias8dev.webfluxblogauthorizationserver.domain.adapters.gson.LocalDateTimeTypeAdapter
import com.mathias8dev.webfluxblogauthorizationserver.domain.adapters.gson.LocalDateTypeAdapter
import com.mathias8dev.webfluxblogauthorizationserver.domain.adapters.gson.ZonedDateTimeTypeAdapter
import com.mathias8dev.webfluxblogauthorizationserver.domain.communication.clients.AuthenticationServerRestClient
import com.mathias8dev.webfluxblogauthorizationserver.domain.communication.clients.AuthorizationServerRestClient
import okhttp3.Cache
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.io.File
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZonedDateTime


@Configuration
class ClientConfiguration {

    @Value("\${webfluxblog.gateway.api-url}")
    private lateinit var gatewayApiUrl: String

    @Bean
    fun okHttpClientBuilder(): OkHttpClient.Builder {
        val cache = Cache(File("cache"), 10 * 1024 * 1024) // 10MB cache file
        val cacheInterceptor = CacheInterceptor()
        val loggingInterceptor = HttpLoggingInterceptor()
        val authInterceptor = AuthInterceptor()
        loggingInterceptor.setLevel(HttpLoggingInterceptor.Level.BODY)
        return OkHttpClient.Builder()
            .cache(cache)
            .addInterceptor(loggingInterceptor)
            .addNetworkInterceptor(cacheInterceptor)
            .addInterceptor(authInterceptor)

    }


    @Bean
    fun provideGson(): Gson {
        return GsonBuilder()
            .registerTypeAdapter(LocalDate::class.java, LocalDateTypeAdapter())
            .registerTypeAdapter(LocalDateTime::class.java, LocalDateTimeTypeAdapter())
            .registerTypeAdapter(ZonedDateTime::class.java, ZonedDateTimeTypeAdapter())
            .registerTypeAdapter(Instant::class.java, InstantTypeAdapter())
            .setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ")
            .create()
    }


    @Bean
    fun authenticationServerRestClient(
        okHttpClientBuilder: OkHttpClient.Builder,
        gson: Gson
    ): AuthenticationServerRestClient {
        return Retrofit.Builder().client(okHttpClientBuilder.build())
            .baseUrl("$gatewayApiUrl/")
            .addConverterFactory(GsonConverterFactory.create(gson))
            .build().create(AuthenticationServerRestClient::class.java)
    }

    @Bean
    fun authorizationServerRestClient(
        okHttpClientBuilder: OkHttpClient.Builder,
        gson: Gson
    ): AuthorizationServerRestClient {
        val okHttpClient = okHttpClientBuilder
            .addInterceptor(BasicAuthInterceptor())
            .build()


        return Retrofit.Builder().client(okHttpClient)
            .baseUrl("$gatewayApiUrl/")
            .addConverterFactory(GsonConverterFactory.create(gson))
            .build().create(AuthorizationServerRestClient::class.java)
    }
}