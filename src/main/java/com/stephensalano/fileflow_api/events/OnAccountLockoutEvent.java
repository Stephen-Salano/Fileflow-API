package com.stephensalano.fileflow_api.events;

import com.stephensalano.fileflow_api.dto.security.SecurityContext;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class OnAccountLockoutEvent extends ApplicationEvent {

    private final String email;
    private final String username;
    private final SecurityContext securityContext;

    public OnAccountLockoutEvent(Object source, String email, String username, SecurityContext securityContext) {
        super(source);
        this.email = email;
        this.username = username;
        this.securityContext = securityContext;
    }
}
