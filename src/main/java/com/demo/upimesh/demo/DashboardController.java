package com.demo.upimesh.demo;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Profile("demo")
public class DashboardController {

    @GetMapping("/")
    public String home() {
        return "dashboard";
    }
}
