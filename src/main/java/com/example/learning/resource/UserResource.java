package com.example.learning.resource;

import com.example.learning.domain.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("user")
public class UserResource {

    @GetMapping("/home")
    public User showUser() {
        return new User();
    }
}
