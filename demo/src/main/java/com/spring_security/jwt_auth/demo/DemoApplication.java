package com.spring_security.jwt_auth.demo;

import com.spring_security.jwt_auth.demo.service.EmailService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}


	@Bean
	CommandLineRunner commandLineRunner(EmailService emailService){
		return args -> {
			emailService.sendEmail("mopup2017@gmail.com", "Greeting", "Hello World!");
		};
	}

}
