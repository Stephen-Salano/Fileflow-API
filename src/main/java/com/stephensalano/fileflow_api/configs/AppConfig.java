package com.stephensalano.fileflow_api.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import ua_parser.Parser;

@Configuration
public class AppConfig {

    @Bean
    public Parser uaParser(){
        return new Parser();
    }

    @Bean
    public JavaMailSender mailSender(){
        return new JavaMailSenderImpl();
    }
}
