package com.max.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplateController {

    @GetMapping("login")
    public String getLoginView(){
        return "login"; // this name must be the same as
                        // the html file inside templates folder
                        // inside the resources but without .html
    }

    @GetMapping("courses")
    public String getCourses(){
        return "courses";
    }
}
