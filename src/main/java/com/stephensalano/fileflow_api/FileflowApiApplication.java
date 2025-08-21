package com.stephensalano.fileflow_api;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.EnableAsync;

@EnableAsync
@SpringBootApplication
public class FileflowApiApplication {

	private static final Logger logger = LoggerFactory.getLogger(FileflowApiApplication.class);

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(FileflowApiApplication.class);
		Environment environment = app.run(args).getEnvironment();

		String activeProfiles = String.join(", ", environment.getActiveProfiles());
		logger.info("Application is running with profiles: {}", activeProfiles);
	}

}
