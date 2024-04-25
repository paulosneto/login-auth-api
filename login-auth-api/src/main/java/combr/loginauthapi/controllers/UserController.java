package combr.loginauthapi.controllers;

import jakarta.persistence.GeneratedValue;
import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping
    public ResponseEntity<String> getUsers(){
        return ResponseEntity.ok("sucesso!");

    }

}
