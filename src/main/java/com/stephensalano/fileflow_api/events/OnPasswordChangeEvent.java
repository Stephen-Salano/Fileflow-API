package com.stephensalano.fileflow_api.events;

import com.stephensalano.fileflow_api.dto.security.SecurityContext;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.context.ApplicationEvent;
@Getter
@Setter
public class OnPasswordChangeEvent extends ApplicationEvent {

    private final String email;
    private final String username;
    private final SecurityContext securityContext;

    public OnPasswordChangeEvent(Object source, @NotBlank(message = "Email cannot be blank") @Email String email, @NotBlank(message = "Username cannot be blank") String username, SecurityContext securityContext) {
        super(source);
        this.email = email;
        this.username = username;
        this.securityContext = securityContext;
    }
}
