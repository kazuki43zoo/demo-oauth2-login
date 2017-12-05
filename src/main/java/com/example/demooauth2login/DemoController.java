package com.example.demooauth2login;

import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;

@Controller
public class DemoController {

  private final RestOperations restOperations = new RestTemplate();
  private final OAuth2AuthorizedClientService authorizedClientService;

  public DemoController(OAuth2AuthorizedClientService authorizedClientService) {
    this.authorizedClientService = authorizedClientService;
  }

  @GetMapping("/")
  public String index(Authentication authentication, Model model) {
    if (OAuth2AuthenticationToken.class.isInstance(authentication)) {
      model.addAttribute("authorizedClient",
          this.getAuthorizedClient(OAuth2AuthenticationToken.class.cast(authentication)));
    }
    return "index";
  }

  @GetMapping("/attributes")
  public String userAttributeAtLogin(Authentication authentication, Model model) {
    if (OAuth2AuthenticationToken.class.isInstance(authentication)) {
      model.addAttribute("attributes",
          OAuth2AuthenticationToken.class.cast(authentication).getPrincipal().getAttributes());
    }
    return "userinfo";
  }

  @GetMapping("/attributes/latest")
  public String userLatestAttribute(Authentication authentication, Model model) {
    if (OAuth2AuthenticationToken.class.isInstance(authentication)) {
      OAuth2AuthorizedClient authorizedClient =
          this.getAuthorizedClient(OAuth2AuthenticationToken.class.cast(authentication));
      String userInfoUri = authorizedClient.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri();
      RequestEntity<Void> requestEntity = RequestEntity.get(URI.create(userInfoUri))
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + authorizedClient.getAccessToken().getTokenValue())
          .build();
      model.addAttribute("attributes", restOperations.exchange(requestEntity, Map.class).getBody());

//    Map userAttributes = WebClient.builder()
//        .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + authorizedClient.getAccessToken().getTokenValue())
//        .build()
//        .get()
//        .uri(userInfoUri)
//        .retrieve()
//        .bodyToMono(Map.class)
//        .block();
//    model.addAttribute("attributes", userAttributes);
    }
    return "userinfo";
  }

  private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken authentication) {
    return this.authorizedClientService.loadAuthorizedClient(
        authentication.getAuthorizedClientRegistrationId(), authentication.getName());
  }


public static void main(String... args) {
  System.out.println(new Pbkdf2PasswordEncoder().encode("test"));
  System.out.println(new Pbkdf2PasswordEncoder().encode("test"));
}
}
