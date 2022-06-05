package ma.enset.ebankingbackend.security.filters;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import ma.enset.ebankingbackend.security.JWTUtil;
import ma.enset.ebankingbackend.security.service.AccountService;
import ma.enset.ebankingbackend.security.service.AccountServiceImpl;
import org.json.JSONObject;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;


public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;
    private AccountService accountServiceImpl;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, AccountServiceImpl accountServiceImpl) {
        this.authenticationManager = authenticationManager;
        this.accountServiceImpl = accountServiceImpl;
    }


    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String requestData = request.getReader().lines().collect(Collectors.joining());
        JSONObject json = new JSONObject(requestData);
        String username = json.getString("username");
        String password =json.getString("password");
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(username,password);
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user = (User) authResult.getPrincipal();
        System.out.println("was success");
        Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
        String JwtAccessToken = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date((System.currentTimeMillis()+ JWTUtil.EXPIRE_ACCESS_TOKEN)))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",user.getAuthorities().stream().map(ga -> ga.getAuthority()).collect(Collectors.toList()))
                         .sign(algorithm);
        String JwtRefreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtil.EXPIRE_REFRESH_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);
        Map<String,String> idToken = new HashMap<>();
        idToken.put("accessT",JwtAccessToken);
        idToken.put("refreshT",JwtRefreshToken);
        idToken.put("user",accountServiceImpl.loadUserByUsernameWithoutPass(user.getUsername()));
        response.setHeader("authorization",JwtAccessToken);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(),idToken);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {

    }
}
