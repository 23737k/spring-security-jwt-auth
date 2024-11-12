package com.spring_security.jwt_auth.demo.exception;

import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(IllegalStateException.class)
  public ResponseEntity<?> handleException(IllegalStateException e) {
    return ResponseEntity.badRequest().body(e.getMessage());
  }

  @ExceptionHandler(EntityNotFoundException.class)
  public ResponseEntity<?> handleException(EntityNotFoundException e) {
    return ResponseEntity.notFound().build();
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<?> handleException(MethodArgumentNotValidException e){
    Set<String> errorMessages = e.getBindingResult().getAllErrors().stream().map(
        DefaultMessageSourceResolvable::getDefaultMessage).collect(Collectors.toSet());
    return ResponseEntity.badRequest().body(errorMessages);
  }
  @ExceptionHandler(ConstraintViolationException.class)
  public ResponseEntity<?> handleException(ConstraintViolationException e){
    Set<String> errorMessages = e.getConstraintViolations().stream().map(ConstraintViolation::getMessage).collect(
        Collectors.toSet());
    return ResponseEntity.badRequest().body(errorMessages);
  }

  @ExceptionHandler(DuplicateEmailException.class)
  public ResponseEntity<?> handleException(DuplicateEmailException e){
    return ResponseEntity.badRequest().body(e.getMessage());
  }




}
