package com.spring_security.jwt_auth.demo.service;

import com.spring_security.jwt_auth.demo.exception.EmailSendException;
import com.spring_security.jwt_auth.demo.model.User;
import com.spring_security.jwt_auth.demo.security.jwt.JwtService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

@Service
@RequiredArgsConstructor
public class EmailService {
  private final JavaMailSender mailSender;
  private final SpringTemplateEngine templateEngine;
  private final JwtService jwtService;
  @Value("${backend.baseUrl}")
  private String baseUrl;

  public void sendEmail(String to, String subject, Map<String, Object> properties, String templateName) {

    try {
      MimeMessage message = mailSender.createMimeMessage();
      MimeMessageHelper helper = new MimeMessageHelper(message);

      String html = getHtmlBody(properties, templateName);

      helper.addTo(to);
      helper.setSubject(subject);
      helper.setText(html, true);
      mailSender.send(message);

    } catch (MessagingException e) {
      throw new EmailSendException("An error occurred while attempting to send the email");
    }
  }


  @Async
  public void sendConfirmationEmail(User user) {
    String verificationCode = jwtService.generateVerificationToken(user);
    String url = baseUrl + "/api/auth/verify-account?token=" + verificationCode;
    Map<String, Object> properties = new HashMap<>();
    properties.put("email", user.getEmail());
    properties.put("url", url);
    sendEmail(user.getEmail(),"Confirm your account", properties, "confirm-account");
  }

  public void sendRecoveryPasswordEmail(){
  }

  private String getHtmlBody(Map<String, Object> properties, String templateName) {
    Context ctx = new Context();
    ctx.setVariables(properties);
    return templateEngine.process(templateName, ctx);
  }
}
