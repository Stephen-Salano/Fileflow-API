package com.stephensalano.fileflow_api.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Description;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.templateresolver.ITemplateResolver;

/**
 * Configuration for email-related beans
 * Sets up thymeleaf for HTML emails
 *
 * Spring sees the two @Bean methods, creates and wires up:
 * - An ItemplateResolver named emailTemplateResolver
 * - A springTemplateEngine named emailTemplateEngine that uses that resolver
 */
@Configuration
public class EmailConfig {

    /**
     * Creates a template resolver for email templates.
     * This allows us to use Thymeleaf templates for our emails
     * Basically, here's how to find the templates
     */

    @Bean
    @Description("Thymelead template resolver for emails")
    public ITemplateResolver emailTemplateResolver(){
        /*
         * The ClassLoaderResolver tells Thymeleaf where and how to find your email templates
         * on the classpath
         */
        ClassLoaderTemplateResolver templateResolver = new ClassLoaderTemplateResolver();
        templateResolver.setPrefix("templates/email/"); // look in src/main/res/templates/email/
        templateResolver.setSuffix(".html"); // only picks files sending in .html
        templateResolver.setTemplateMode("HTML"); // Parse them as HTML
        templateResolver.setCharacterEncoding("UTF-8"); // Read files as UTF-8 text
        templateResolver.setCacheable(false); // Don't cache so changes appear immediately
        return templateResolver;
    }

    /**
     * The central Thymeleaf component that makes a template name plus variables
     * Basically here's the processor that uses that resolver
     * @return the template engine
     */
    @Bean
    @Description("Thymeleaf template engine for emails")
    public SpringTemplateEngine emailTemplateEngine(){
        SpringTemplateEngine templateEngine = new SpringTemplateEngine();
        templateEngine.addTemplateResolver(emailTemplateResolver());
        return templateEngine;
    }
}
