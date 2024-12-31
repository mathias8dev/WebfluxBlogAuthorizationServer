package com.mathias8dev.webfluxblogauthorizationserver.domain.events.scheduling

import com.mathias8dev.webfluxblogauthorizationserver.models.Authorization
import com.mathias8dev.webfluxblogauthorizationserver.services.JpaOAuth2AuthorizationService
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import java.time.LocalDateTime

@Component
class ExpiredOAuthTokenClearScheduler(
    private val oauthService: JpaOAuth2AuthorizationService
) {

    private val logger = LoggerFactory.getLogger(this.javaClass)

    @Scheduled(cron = "0 0 0 1 1,4,7,10 ?") // At midnight on the first day of every quarter
    fun clearExpiredOAuthToken() {
        kotlin.runCatching {

            logger.info("Clearing useless OAuth tokens at {}", LocalDateTime.now())
            oauthService.findAll().forEach {
                val oauth2Authorization = Authorization.toObject(it, oauthService.getRegisteredClient(it))
                if (oauth2Authorization.refreshToken?.isActive == false &&
                    oauth2Authorization.accessToken?.isActive == false
                ) {
                    oauthService.remove(oauth2Authorization)
                }
            }

        }
    }


}