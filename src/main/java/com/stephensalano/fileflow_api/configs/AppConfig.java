package com.stephensalano.fileflow_api.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ua_parser.Parser;

@Configuration
public class AppConfig {

    @Bean
    public Parser uaParser(){
        return new Parser();
    }
}
