package com.example.demooauth2login;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

  @GetMapping("/login")
  public String viewLoginPage() {
    return "loginForm";
  }

}
