package combr.loginauthapi.controllers;

import combr.loginauthapi.domain.Users;
import combr.loginauthapi.dto.LoginRequestDTO;
import combr.loginauthapi.dto.RegisterResponseDTO;
import combr.loginauthapi.dto.ResponseDTO;
import combr.loginauthapi.infra.security.TokenService;
import combr.loginauthapi.repositories.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;


@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthContoller {

    private final UsersRepository usersRepository;

    private  final PasswordEncoder passwordEncoder;

    private final TokenService tokenService;


    @PostMapping("/login")
    private ResponseEntity login(@RequestBody LoginRequestDTO body){

        Users users = usersRepository.findByEmail(body.email()).orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if(passwordEncoder.matches(body.password(), users.getPassword())){
                String token = this.tokenService.generateToken(users);

                return ResponseEntity.ok().body(new ResponseDTO(users.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    }


    @PostMapping("/register")
    private ResponseEntity register(@RequestBody RegisterResponseDTO body){
        // busca o usuario informado pra ver se existe um cadastro
        Optional<Users> users = usersRepository.findByEmail(body.email());
        // Se houver cadastro para o login informado, devolve o token, caso nao exista o usuário,
        if(users.isEmpty()){
            Users nUser = new Users();
            nUser.setPassword(passwordEncoder.encode(body.password()));
            nUser.setEmail(body.email());
            nUser.setName(body.name());
            this.usersRepository.save(nUser);

            String token = this.tokenService.generateToken(nUser);
            return ResponseEntity.ok().body(new ResponseDTO(nUser.getName(), token));
        }

        return ResponseEntity.badRequest().build();
    }

}

