package com.thejackfolio.microservices.apigateway.exception;

public class HeaderException extends RuntimeException{

    public HeaderException(String message) {
        super(message);
    }
}
