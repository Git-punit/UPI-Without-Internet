package com.upioffline.protocol;

public class InvalidEnvelopeException extends Exception {
    public InvalidEnvelopeException(String message) {
        super(message);
    }

    public InvalidEnvelopeException(String message, Throwable cause) {
        super(message, cause);
    }
}
