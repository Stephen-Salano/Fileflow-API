package com.stephensalano.fileflow_api.exceptions;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

/**
 * catches validation errors (MethodArgumentNotValidException) and our custom BadRequestExceptions, then return a JSON
 * body with HTTP 400
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handles Bean Validation failures (e.g. when `@valid` fails on RegisterRequest)
     * @param ex exception class passed as argument
     * @return ResponseEntity
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(
            MethodArgumentNotValidException ex
    ){
        Map<String, String> fieldErrors = new HashMap<>();

        // collect all field errors into a simple map: "field" -> "message"
        for (FieldError error: ex.getBindingResult().getFieldErrors()){
            fieldErrors.put(error.getField(), error.getDefaultMessage());
        }

        Map<String, Object> body = new HashMap<>();
        body.put("success", false);
        body.put("errors", fieldErrors);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        return new ResponseEntity<>(body, headers, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<Map<String, Object>> handleBadRequestException(
            BadRequestException ex
    ){
        Map<String, Object> body = new HashMap<>();
        body.put("success", false);
        body.put("message", ex.getMessage());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        return new ResponseEntity<>(body, headers, HttpStatus.BAD_REQUEST);
    }

    // 3) Resource Not FoundException -> HTTP 404
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleResourceNotFound(ResourceNotFoundException ex){
        Map<String, Object> body = new HashMap<>();
        body.put("success", false);
        body.put("message", ex.getMessage());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        return new ResponseEntity<>(body, headers, HttpStatus.NOT_FOUND);
    }

    // 4) AccessDeniedException -> HTTP 403
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>>handleAccessDenied(AccessDeniedException ex){
        Map<String, Object> body = new HashMap<>();
        body.put("success", false);
        body.put("message", ex.getMessage());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        return new ResponseEntity<>(body, headers, HttpStatus.FORBIDDEN);
    }

    // 5) A catch‐all fallback
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String,Object>> handleAllOtherExceptions(
            Exception ex
    ) {
        Map<String,Object> body = new HashMap<>();
        body.put("success", false);
        body.put("message", "An unexpected error occurred");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return new ResponseEntity<>(body, headers, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
