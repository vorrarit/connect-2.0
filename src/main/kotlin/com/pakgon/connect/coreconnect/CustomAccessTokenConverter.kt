package com.pakgon.connect.coreconnect

import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter
import org.springframework.stereotype.Component

@Component
class CustomAccessTokenConverter: DefaultAccessTokenConverter() {

    override fun extractAuthentication(claims: MutableMap<String, *>?): OAuth2Authentication {
        val authentication = super.extractAuthentication(claims)
        authentication.details = claims
        return authentication
    }
}