package com.pakgon.connect.coreconnect

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.core.io.ClassPathResource
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.jwt.crypto.sign.Signer
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer
import org.springframework.security.oauth2.provider.token.DefaultTokenServices
import org.springframework.security.oauth2.provider.token.TokenEnhancer
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory

@Configuration
@EnableAuthorizationServer
class AuthServerConfigJwt: AuthorizationServerConfigurerAdapter() {

    @Autowired
    @Qualifier("authenticationManagerBean")
    private lateinit var authenticationManager:AuthenticationManager

    override fun configure(oauthServer: AuthorizationServerSecurityConfigurer?) {
        oauthServer!!.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
    }

    override fun configure(clients: ClientDetailsServiceConfigurer?) {
        clients!!.inMemory()
                .withClient("sampleClientId")
                    .authorizedGrantTypes("implicit")
                    .scopes("read", "write", "foo", "bar")
                    .autoApprove(false)
                    .accessTokenValiditySeconds(3600).redirectUris("http://localhost:8083/")

                .and().withClient("fooClientIdPassword")
                    .secret(passwordEncoder().encode("secret"))
                    .authorizedGrantTypes("password", "authorization_code", "refresh_token")
                    .scopes("foo", "read", "write")
                    .accessTokenValiditySeconds(3600)
                    // 1 hour
                    .refreshTokenValiditySeconds(2592000)
                    // 30 days
                    .redirectUris("xxx")

                .and().withClient("barClientIdPassword")
                    .secret(passwordEncoder().encode("secret"))
                    .authorizedGrantTypes("password", "authorization_code", "refresh_token")
                    .scopes("bar", "read", "write")
                    .accessTokenValiditySeconds(3600)
                    // 1 hour
                    .refreshTokenValiditySeconds(2592000) // 30 days

                .and().withClient("testImplicitClientId")
                    .authorizedGrantTypes("implicit")
                    .scopes("read", "write", "foo", "bar")
                    .autoApprove(true)
                    .redirectUris("xxx");
    }

    @Bean
    @Primary
    fun tokenServices(): DefaultTokenServices {
        val defaultTokenServices = DefaultTokenServices()
        defaultTokenServices.setTokenStore(tokenStore())
        defaultTokenServices.setSupportRefreshToken(true)
        return defaultTokenServices
    }

    override fun configure(endpoints: AuthorizationServerEndpointsConfigurer?) {
        val enhancerChain = TokenEnhancerChain()
        enhancerChain.setTokenEnhancers(listOf(tokenEnhancer(), accessTokenConverter()))
//        endpoints!!.tokenStore(tokenStore())
//                .tokenEnhancer(accessTokenConverter())
//                .authenticationManager(authenticationManager)
        val tokenConverter = JwtAccessTokenConverter()
        tokenConverter.setSigningKey("123")
        val keyStoreKeyFactory = KeyStoreKeyFactory(ClassPathResource("mytest.jks"), "password".toCharArray())
        tokenConverter.setKeyPair(keyStoreKeyFactory.getKeyPair("mytest"))
        endpoints!!.tokenStore(JwtTokenStore(tokenConverter))
                .tokenEnhancer(tokenConverter)
                .authenticationManager(authenticationManager)

    }

    @Bean
    fun tokenStore(): TokenStore {
        return JwtTokenStore(accessTokenConverter())
    }

    @Bean
    fun accessTokenConverter():JwtAccessTokenConverter {
        val converter = JwtAccessTokenConverter()
        converter.setSigningKey("123")
        return converter
    }

    @Bean
    fun tokenEnhancer(): TokenEnhancer {
        return CustomTokenEnhancer()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        val idForEncode = "bcrypt"
        val encoderMap = mutableMapOf<String, PasswordEncoder>(
                idForEncode to BCryptPasswordEncoder()
        )
        return DelegatingPasswordEncoder(idForEncode, encoderMap)
    }

}