package ma.enset.ebankingbackend.security.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import ma.enset.ebankingbackend.security.entities.AppRole;
import ma.enset.ebankingbackend.security.entities.AppUser;
import ma.enset.ebankingbackend.security.entities.AppUserWithoutPass;
import ma.enset.ebankingbackend.security.repositories.AppRoleRepository;
import ma.enset.ebankingbackend.security.repositories.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
@AllArgsConstructor
public class AccountServiceImpl implements AccountService {
    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;
    private PasswordEncoder passwordEncoder;
    @Override
    public AppUser addNewUser(AppUser appUser) {
        String pw = appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(pw));
        return appUserRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser = appUserRepository.findByUsername(username);
        AppRole appRole = appRoleRepository.findByRoleName(roleName);
        if(appUser!=null || appRole!=null){
            appUser.getAppRoles().add(appRole);
        }else{
            throw new RuntimeException("username or rolename is not found");
        }

    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }
    @Override
    public String loadUserByUsernameWithoutPass(String username) throws JsonProcessingException {
        AppUser appUser =appUserRepository.findByUsername(username);
        AppUserWithoutPass appUserWithoutPass = new AppUserWithoutPass();
        appUserWithoutPass.setUsername(appUser.getUsername());
        appUserWithoutPass.setId(appUser.getId());
        appUser.getAppRoles().forEach(r -> appUserWithoutPass.getAppRoles().add(r.getRoleName()));
        ObjectMapper mapper = new ObjectMapper();
        String Json =  mapper.writeValueAsString(appUserWithoutPass);
        return Json;
    }

    @Override
    public List<AppUser> listUsers() {
        return appUserRepository.findAll();
    }
}
