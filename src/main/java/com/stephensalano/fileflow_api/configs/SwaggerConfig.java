package com.stephensalano.fileflow_api.configs;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;

import java.util.stream.Stream;
@Profile({"dev", "test"})
@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI customOpenAPI(Environment environment){
        String activeProfiles = Stream.of(environment.getActiveProfiles())
                .findFirst()
                .orElse("default");
        // Only allow Swagger in dev/test environments
        if (!activeProfiles.equalsIgnoreCase("dev") && !activeProfiles.equalsIgnoreCase("test")){
            return null; // this will disable swagger UI on prod env
        }

        return new OpenAPI()
                .info(new Info()
                        .title("FileFlow API Docs")
                        .version("v1")
                        .description("Secure media management backend using Spring Boot and JWT authentication")
                )
                .components(new Components()
                        .addSecuritySchemes("bearerAuth",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .in(SecurityScheme.In.HEADER)
                                        .name("Authorization")
                        )
                )
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
    }
}
