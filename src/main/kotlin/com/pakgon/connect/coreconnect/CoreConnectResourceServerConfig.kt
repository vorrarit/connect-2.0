package com.pakgon.connect.coreconnect

import org.apache.tomcat.util.http.fileupload.IOUtils
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.core.io.ClassPathResource
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer
import org.springframework.security.oauth2.provider.token.DefaultTokenServices
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore
import java.io.InputStreamReader

@Configuration
@EnableResourceServer
class CoreConnectResourceServerConfig: ResourceServerConfigurerAdapter() {

    @Autowired
    private lateinit var customAccessTokenConverter: CustomAccessTokenConverter

    @Bean
    fun tokenStore(): TokenStore {
        return JwtTokenStore(accessTokenConverter())
    }

    @Bean
    fun accessTokenConverter(): JwtAccessTokenConverter {
//        val converter = JwtAccessTokenConverter()
//        converter.accessTokenConverter = customAccessTokenConverter
//        converter.setSigningKey("123")
//        return converter

        val converter = JwtAccessTokenConverter()
        val resource = ClassPathResource("public.txt")
        val publicKey = InputStreamReader(resource.inputStream).readText()
        converter.setVerifierKey(publicKey)
        return converter
    }

    @Bean
    @Primary
    fun tokenServices(): DefaultTokenServices {
        val defaultTokenServices = DefaultTokenServices()
        defaultTokenServices.setTokenStore(tokenStore())
        return defaultTokenServices
    }

    override fun configure(config: ResourceServerSecurityConfigurer?) {
        config!!.tokenServices(tokenServices())
    }

    override fun configure(http: HttpSecurity?) {
        http!!.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .and().requestMatchers()
                .antMatchers("/user/me")
                .and().authorizeRequests().antMatchers("/user/me")
                .access("#oauth2.hasScope('read')")
    }
}