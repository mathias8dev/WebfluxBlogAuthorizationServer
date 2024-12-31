package com.mathias8dev.webfluxblogauthorizationserver.domain.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.annotation.EnableAsync
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler


@Configuration
@EnableScheduling
@EnableAsync
class SchedulerConfig {

    @Bean
    fun threadPoolTaskScheduler(): ThreadPoolTaskScheduler {
        val threadPoolTaskScheduler = ThreadPoolTaskScheduler()
        threadPoolTaskScheduler.poolSize = 5
        threadPoolTaskScheduler.setThreadNamePrefix(
            "ThreadPoolTaskScheduler"
        )
        return threadPoolTaskScheduler
    }


}