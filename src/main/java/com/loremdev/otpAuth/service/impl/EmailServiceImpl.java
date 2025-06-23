package com.loremdev.otpAuth.service.impl;

import com.loremdev.otpAuth.service.EmailService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor

public class EmailServiceImpl implements EmailService {
    private final JavaMailSender mailSender;

    @Value("${spring.mail.properties.mail.smtp.from}")
    private String fromEmail;

    @Override
    public void sendWelcomeEmail(String toEmail, String name) {
        SimpleMailMessage mailMessage= new SimpleMailMessage();
        mailMessage.setFrom(fromEmail);
        mailMessage.setTo(toEmail);
        mailMessage.setSubject("Welcome to Our Service");
        mailMessage.setText("Hello " + name + ",\n\n" +
                "Thank you for registering with us! We are excited to have you on board.\n\n" +
                "Best regards,\n" +
                "The Team");
        mailSender.send(mailMessage);
    }

    @Override
    public void sendResetOtpEmail(String toEmail, String otp){
        SimpleMailMessage mailMessage= new SimpleMailMessage();
        mailMessage.setFrom(fromEmail);
        mailMessage.setTo(toEmail);
        mailMessage.setSubject("Password Reset OTP");
        mailMessage.setText("Your OTP for password reset is: " + otp + "\n\n" +
                "This OTP is valid for 15 minutes.\n\n" +
                "If you did not request a password reset, please ignore this email.\n\n" +
                "Best regards,\n" +
                "The Team");
        mailSender.send(mailMessage);
    }
}
