package com.spring_security.jwt_auth.demo.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class DemoController {

  @GetMapping("/hello-world")
  public String hello() {
    return "Hello World";
  }
}
