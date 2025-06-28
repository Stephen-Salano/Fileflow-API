package com.stephensalano.fileflow_api.events;

import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class OnPasswordResetSuccessEvent extends ApplicationEvent {
    private final String email;
    private final String username;

    public OnPasswordResetSuccessEvent(Object source, String email, String username) {
        super(source);
        this.email = email;
        this.username = username;
    }

}
