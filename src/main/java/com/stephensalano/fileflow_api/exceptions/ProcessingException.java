package com.stephensalano.fileflow_api.exceptions;

public class ProcessingException extends RuntimeException {
    public ProcessingException(String message) {
        super(message);
    }
}
