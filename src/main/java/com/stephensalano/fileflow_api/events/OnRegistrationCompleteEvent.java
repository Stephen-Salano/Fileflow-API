package com.stephensalano.fileflow_api.events;

import lombok.Getter;
import lombok.Setter;
import org.springframework.context.ApplicationEvent;

/**
 * This event carries the data needed to send a verification email
 * after the account/user/token have already been committed
 *
 * By subclassing `ApplicationEvent`, you can publish it via Spring's `ApplicationEventPublisher`.
 * Once transaction in registerUser() commits, Spring will fire this event
 */


@Getter
@Setter
public class OnRegistrationCompleteEvent extends ApplicationEvent {

    private final String email;
    private final String username;
    private final String token;


    public OnRegistrationCompleteEvent(Object source, String email, String username, String token) {
        super(source);
        this.email = email;
        this.username = username;
        this.token = token;
    }
}
