package com.example.demooauth2login;

import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
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
  public String index(OAuth2AuthenticationToken authentication, Model model) {
    model.addAttribute("authorizedClient", this.getAuthorizedClient(authentication));
    return "index";
  }

  @GetMapping("/attributes")
  public String userAttributeAtLogin(@AuthenticationPrincipal OAuth2User oauth2User, Model model) {
    model.addAttribute("attributes", oauth2User.getAttributes());
    return "userinfo";
  }

  @GetMapping("/attributes/latest")
  public String userLatestAttribute(OAuth2AuthenticationToken authentication, Model model) {
    OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authentication);
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

    return "userinfo";
  }

  private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken authentication) {
    return this.authorizedClientService.loadAuthorizedClient(
        authentication.getAuthorizedClientRegistrationId(), authentication.getName());
  }

}
