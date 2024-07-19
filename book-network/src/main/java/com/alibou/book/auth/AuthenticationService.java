package com.alibou.book.auth;

import com.alibou.book.email.EmailService;
import com.alibou.book.email.EmailTemplateName;
import com.alibou.book.role.RoleRepository;
import com.alibou.book.security.JwtService;
import com.alibou.book.user.Token;
import com.alibou.book.user.TokenRepository;
import com.alibou.book.user.User;
import com.alibou.book.user.UserRepository;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
// import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Value("${application.mailing.frontend.activation-url}")
    private String activationUrl;

    public void register(RegistrationRequest request) throws MessagingException {
        // Get the User ROLE or Throw an Exception
        var userRole = roleRepository.findByName("USER")
                // TODO: better exception handling
                .orElseThrow(() -> new IllegalArgumentException("ROLE USER was not initialized"));

        // Verify if user already exist
        var currentUser = userRepository.findByEmail(request.getEmail());

        // If User already exist on database, just send a new email with the account activation code.
        if(currentUser.isPresent()){
            // Send validation email
            sendValidationEmail(currentUser.get());
        }else{
            // Create and set an User object
            var user = User.builder()
                    .firstName(request.getFirstname())
                    .lastName(request.getLastname())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .accountLocked(false)
                    .enabled(false)     // Need to set enabled to FALSE
                    .roles(List.of(userRole))
                    .build();

            // Save the User object
            userRepository.save(user);

            // Send validation email
            sendValidationEmail(user);
        }

    }

    private void sendValidationEmail(User user) throws MessagingException {
        var newToken = generateAndSaveActivationToken(user);
        // Send validation email to User
        emailService.sendEmail(
                user.getEmail(),
                user.fullName(),
                EmailTemplateName.ACTIVATE_ACCOUNT,
                activationUrl,
                newToken,
                "Account Activation"
        );

    }

    private String generateAndSaveActivationToken(User user) {
        // Generate a validate token String
        String generatedToken = genetareActivationCode(6);
        var token = Token.builder()
                .token(generatedToken)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .user(user)
                .build();

        // Save generated Token in database
        tokenRepository.save(token);
        // Return token
        return generatedToken;
    }

    /**
     * Method with algorithm responsible to create a valid token String
     * @param length
     * @return String token
     */
    private String genetareActivationCode(int length) {
        String characters = "0123456789";
        StringBuilder codeBuilder = new StringBuilder();
        SecureRandom secureRandom = new SecureRandom();
        for (int i = 0; i < length; i++) {
            int randomIndex = secureRandom.nextInt(characters.length());    // from 0..9
            codeBuilder.append(characters.charAt(randomIndex));
        }
        return codeBuilder.toString();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // TODO: implement the validate step

        // Set the authentication manager
        var auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // Create the claims
        var claims = new HashMap<String, Object>();
        // Get the User
        var user = ((User)auth.getPrincipal());

        // Set the claim user
        claims.put("fullname", user.fullName());

        // Generate token
        var jwtToken = jwtService.generateToken(claims, user);

        return AuthenticationResponse.builder()
                .token(jwtToken).build();

    }

//    @Transactional
    public void activateAccount(String token) throws MessagingException {
        // Get the saved token
        Token savedToken = tokenRepository.findByToken(token)
                // TODO: implement better exception
                .orElseThrow(() -> new RuntimeException("Invalid token"));
        // Check if token is valid
        if (LocalDateTime.now().isAfter(savedToken.getExpiresAt())){
            // If token has expired, send new validation email
            sendValidationEmail(savedToken.getUser());
            // Throw a new exception
            throw new RuntimeException("Activation token has expired. A new token has been sent to the same email address " + savedToken.getUser().getEmail());
        }

        // If token is not expired, get User (in this step we decide to fetch user from database instead of fetch from savedToken)
        var user = userRepository.findById(savedToken.getUser().getId())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
//        var user = savedToken.getUser();

        // Enable the user
        user.setEnabled(true);

        // Save the user
        userRepository.save(user);

        // Update the validate the token
        savedToken.setValidatedAt(LocalDateTime.now());

        // Update the savedToken in the database
        tokenRepository.save(savedToken);
    }
}
