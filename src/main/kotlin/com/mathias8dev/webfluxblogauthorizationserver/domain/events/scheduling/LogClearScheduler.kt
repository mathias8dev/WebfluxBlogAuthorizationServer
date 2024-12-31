package com.mathias8dev.webfluxblogauthorizationserver.domain.events.scheduling

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import java.nio.file.Files
import java.nio.file.Paths
import java.time.LocalDateTime

@Component
class LogClearScheduler {

    private val logger = LoggerFactory.getLogger(javaClass)

    @Value("\${logging.file.name}")
    private lateinit var logFilePath: String


    @Scheduled(cron = "0 0 * * * ?") // this will run every hour
    fun clearLogFile() {
        kotlin.runCatching {
            Files.write(Paths.get(logFilePath), "".toByteArray())
            logger.info("Log file cleared at {}", LocalDateTime.now())
        }
    }


}