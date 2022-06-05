package ma.enset.ebankingbackend.security.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import ma.enset.ebankingbackend.security.JWTUtil;
import ma.enset.ebankingbackend.security.entities.AppRole;
import ma.enset.ebankingbackend.security.entities.AppUser;
import ma.enset.ebankingbackend.security.entities.RoleUserForm;
import ma.enset.ebankingbackend.security.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@CrossOrigin
@RequestMapping("/auth")
@AllArgsConstructor
public class AccountRestController {
    AccountService accountService;
    @PostAuthorize("hasAnyAuthority('USER')")
    @GetMapping("/users")
    List<AppUser> appUsers(){
        return accountService.listUsers();
    }
    @PostAuthorize("hasAnyAuthority('ADMIN')")
    @PostMapping("/users")
    AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }
    @PostAuthorize("hasAnyAuthority('ADMIN')")

    @PostMapping("/roles")
    AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }
    @PostAuthorize("hasAnyAuthority('ADMIN')")
    @PostMapping("/addRoleToUser")
    void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRoleName());
    }
    @PostAuthorize("hasAnyAuthority('USER')")
    @GetMapping("/profile")
    public AppUser profile(Principal principal){
        return accountService.loadUserByUsername(principal.getName());

    }
    @PostMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        System.out.println("**************************** refresh authentication request"+request.getHeader(JWTUtil.AUTH_HEADER));
        String authToken = request.getHeader(JWTUtil.AUTH_HEADER);
        if(authToken!=null && authToken.startsWith(JWTUtil.PREFIX)){
            try{
                String jwt = authToken.substring(JWTUtil.PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decoded = jwtVerifier.verify(jwt);
                String username = decoded.getSubject();
                AppUser appUser = accountService.loadUserByUsername(username);
                String JwtAccessToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtil.EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",appUser.getAppRoles().stream().map(r -> r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String> idToken = new HashMap<>();
                idToken.put("accessT",JwtAccessToken);
                idToken.put("refreshT",jwt);
                response.setHeader("authorization",JwtAccessToken);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);
                System.out.println(idToken);
                System.out.println(idToken);
                System.out.println(idToken);
            }catch (Exception e){
                System.out.println("error");
                System.out.println(e);
                throw e;
            }
        }
        else{
            new RuntimeException("Refresh Token required");
        }

    }
}

