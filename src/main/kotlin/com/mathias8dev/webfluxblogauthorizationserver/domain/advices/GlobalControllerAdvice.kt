package com.mathias8dev.webfluxblogauthorizationserver.domain.advices

import com.mathias8dev.webfluxblogauthorizationserver.domain.exceptions.HttpException
import org.springframework.core.env.Environment
import org.springframework.core.env.get
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.context.request.WebRequest
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler
import java.util.*


@ControllerAdvice
class GlobalExceptionAdvice(
    private val env: Environment
) : ResponseEntityExceptionHandler() {


    @ExceptionHandler(value = [IllegalArgumentException::class, IllegalStateException::class])
    protected fun handleConflict(
        ex: Exception, request: WebRequest
    ): ResponseEntity<Any>? {
        val body = getErrorsBody(ex, request, HttpStatus.CONFLICT)
        return handleExceptionInternal(
            ex, body,
            HttpHeaders(), HttpStatus.CONFLICT, request
        )
    }


    @ExceptionHandler(value = [HttpException::class])
    protected fun handleHttpException(
        ex: Exception, request: WebRequest
    ): ResponseEntity<Any>? {
        ex as HttpException

        val body = getErrorsBody(ex, request, ex.httpStatus)
        return handleExceptionInternal(
            ex, body,
            HttpHeaders(), ex.httpStatus, request
        )
    }


    @ExceptionHandler(value = [Exception::class])
    protected fun handleGlobalException(
        ex: Exception, request: WebRequest
    ): ResponseEntity<Any>? {

        val body = getErrorsBody(ex, request, HttpStatus.INTERNAL_SERVER_ERROR)
        return handleExceptionInternal(
            ex, body,
            HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR, request
        )
    }

    private fun getErrorsBody(exception: Exception, request: WebRequest, status: HttpStatus): Map<String, String> {
        val body = mutableMapOf<String, String>()
        body["timestamp"] = Date().toString()
        body["path"] = request.getDescription(false)
        body["status"] = status.value().toString()
        body["error"] = status.reasonPhrase
        body["message"] = exception.message ?: "An error occurred"
        body["exception"] = exception.javaClass.name
        if (env["debug"].toBoolean()) body["trace"] = exception.stackTraceToString()

        return body
    }

}