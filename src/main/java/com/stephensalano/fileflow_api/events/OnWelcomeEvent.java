package com.stephensalano.fileflow_api.events;

import lombok.Getter;
import lombok.Setter;
import org.springframework.context.ApplicationEvent;

/**
 * Event fired after email verification is complete
 * Used to send welcome email after transaction commits
 */
@Getter
@Setter
public class OnWelcomeEvent extends ApplicationEvent {

    private final String email;
    private final String username;

    public OnWelcomeEvent(Object source, String email, String username){
        super(source);
         this.email = email;
         this.username = username;
    }
}
