package com.stephensalano.fileflow_api.services.user;

import com.stephensalano.fileflow_api.repository.AccountRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AccountDetailsService implements UserDetailsService {

    // DI Account repo
    private final AccountRepository accountRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return accountRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("No account: " + username)
        );
    }
}
