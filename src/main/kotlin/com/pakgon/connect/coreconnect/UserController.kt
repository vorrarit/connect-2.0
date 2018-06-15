package com.pakgon.connect.coreconnect

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal

@RestController
class UserController {

    @GetMapping("/user/me")
    fun user(principal: Principal): Principal {
        return principal
    }
}