package com.stephensalano.fileflow_api.services.user;

import com.stephensalano.fileflow_api.dto.requests.ChangePasswordRequest;
import com.stephensalano.fileflow_api.entities.Account;
import jakarta.validation.Valid;


public interface UserService {

    void changePassword(Account authenticatedAccount, @Valid ChangePasswordRequest changePasswordRequest);
}
