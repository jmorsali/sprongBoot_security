package com.example.demo.student;



import com.example.demo.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/auth")
public class AuthController {
    private final static Logger logger = LoggerFactory.getLogger(AuthController.class);
   private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }


    @GetMapping("token")
    public String token(Authentication authentication) {
        if(authentication==null)
            return "N/A";
        logger.debug("Token Requested : '{}'", authentication.getName());
        String token = tokenService.generateToken(authentication);
        logger.debug("Token granted : {}", token);
        return token;
    }
}
