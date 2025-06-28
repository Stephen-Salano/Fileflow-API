package com.stephensalano.fileflow_api.events;

import lombok.Getter;
import lombok.Setter;
import org.springframework.context.ApplicationEvent;

@Getter
@Setter
public class OnPasswordResetRequestEvent extends ApplicationEvent {

    private final String email;
    private final String username;
    private String token;


    public OnPasswordResetRequestEvent(Object source, String email, String username, String token) {
        super(source);
        this.email = email;
        this.username = username;
        this.token = token;
    }

}
