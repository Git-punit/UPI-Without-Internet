package com.upioffline.backend;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/** An error the client can act on. Rendered as {@code {"error": CODE, "message": text}}. */
public class ApiException extends RuntimeException {

    final HttpStatus status;
    final String code;

    public ApiException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    static ApiException badRequest(String message) {
        return new ApiException(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", message);
    }

    @RestControllerAdvice
    static class Handler {
        @ExceptionHandler(ApiException.class)
        ResponseEntity<Map<String, String>> api(ApiException e) {
            return ResponseEntity.status(e.status).body(Map.of("error", e.code, "message", e.getMessage()));
        }

        @ExceptionHandler(HttpMessageNotReadableException.class)
        ResponseEntity<Map<String, String>> unreadable(HttpMessageNotReadableException e) {
            return api(badRequest("request body is not valid JSON for this endpoint"));
        }
    }
}
