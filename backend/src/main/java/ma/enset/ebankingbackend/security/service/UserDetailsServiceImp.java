package ma.enset.ebankingbackend.security.service;


import lombok.AllArgsConstructor;
import ma.enset.ebankingbackend.security.entities.AppUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

@Service
@AllArgsConstructor
public class UserDetailsServiceImp implements UserDetailsService {
    AccountService accountService;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = accountService.loadUserByUsername(username);
        Collection<GrantedAuthority> grantedAuthorityCollection = new ArrayList<>();
        appUser.getAppRoles().forEach(appRole -> {
            grantedAuthorityCollection.add(new SimpleGrantedAuthority(appRole.getRoleName()));
        });
        return new User(appUser.getUsername(),appUser.getPassword(),grantedAuthorityCollection);
    }
}
