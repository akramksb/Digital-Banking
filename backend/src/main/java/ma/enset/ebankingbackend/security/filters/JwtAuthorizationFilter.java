package ma.enset.ebankingbackend.security.filters;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import ma.enset.ebankingbackend.security.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getServletPath().equals("/auth/refreshToken") || request.getServletPath().equals("/login")){
            filterChain.doFilter(request,response);
        }
        else {
            String authorizationToken = request.getHeader(JWTUtil.AUTH_HEADER);
            if(authorizationToken!=null && authorizationToken.startsWith(JWTUtil.PREFIX)){
                try{
                    String jwt = authorizationToken.substring(JWTUtil.PREFIX.length());
                    Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                    DecodedJWT decoded = jwtVerifier.verify(jwt);
                    String username = decoded.getSubject();
                    String[] roles = decoded.getClaim("roles").asArray(String.class);
                    Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
                    for(String r:roles){
                        grantedAuthorities.add(new SimpleGrantedAuthority(r));
                    }
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                            = new UsernamePasswordAuthenticationToken(username,null,grantedAuthorities);
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    filterChain.doFilter(request,response);
                }catch (AuthenticationException | TokenExpiredException e){
                    response.resetBuffer ();
                    response.setStatus (HttpServletResponse.SC_UNAUTHORIZED);
                    response.flushBuffer ();
                    new RuntimeException(e);
                }
            }
            else{
                filterChain.doFilter(request,response);
            }

        }

    }
}
