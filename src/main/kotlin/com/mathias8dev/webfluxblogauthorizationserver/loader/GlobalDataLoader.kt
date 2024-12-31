package com.mathias8dev.webfluxblogauthorizationserver.loader

import com.mathias8dev.webfluxblogauthorizationserver.domain.annotations.DataLoader
import com.mathias8dev.webfluxblogauthorizationserver.repository.ClientRepository
import org.springframework.context.ApplicationListener
import org.springframework.context.event.ContextRefreshedEvent


@DataLoader
class GlobalDataLoader(
    private val clientDataLoader: ClientDataLoader,
    private val clientRepository: ClientRepository
) : ApplicationListener<ContextRefreshedEvent?> {
    private var alreadySetup = false


    private val isDataAlreadyLoaded: Boolean
        get() = clientRepository.findAll().isNotEmpty()

    override fun onApplicationEvent(event: ContextRefreshedEvent) {
        if (isDataAlreadyLoaded) alreadySetup = true
        if (alreadySetup) return

        clientDataLoader.populate()
        alreadySetup = true
    }
}