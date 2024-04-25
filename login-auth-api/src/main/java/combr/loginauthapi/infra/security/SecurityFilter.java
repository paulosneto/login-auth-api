package combr.loginauthapi.infra.security;

import combr.loginauthapi.domain.Users;
import combr.loginauthapi.repositories.UsersRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class SecurityFilter extends OncePerRequestFilter {

    // Injeção de dependencia do TokenService
    @Autowired
    TokenService tokenService;

    // Injeção de dependencia do UsersRepository
    @Autowired
    UsersRepository usersRepository;

    // Filtro interno para poder tratar o token recebido na requisição
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //Recupera o token enviado
        var token = this.recoveryToken(request);
        // Passa o token informado para ser validado pala classe "TokenService"
        var login = tokenService.validateToken(token);
        // Se o token for diferente de null faz a validação para devolver a requisição apenas o token válido
        if(login != null){

            Users user = usersRepository.findByEmail(login).orElseThrow(() -> new RuntimeException("User not found"));
            // Define as regras de acesso para o login determinado
            var authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
            // Salva o contexto do usuario o token de autenticacao
            var authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);

            SecurityContextHolder.getContext().setAuthentication(authentication);

        }

        // Faz a chamada do proximo filtro
        filterChain.doFilter(request, response);
    }

    // Trata o token enviado na requisição apagando o
    // inicio padrão deixando somento o token válido
    private String recoveryToken(HttpServletRequest request){
        var authHeader = request.getHeader("Authorization");
        if(authHeader == null) return null;
        return authHeader.replace("Bearer ", "");
    }
}
