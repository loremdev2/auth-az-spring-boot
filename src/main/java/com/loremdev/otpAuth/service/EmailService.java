package com.loremdev.otpAuth.service;

public interface EmailService {

    public void sendWelcomeEmail(String toEmail, String name);

    public void sendResetOtpEmail(String toEmail, String otp);
}
