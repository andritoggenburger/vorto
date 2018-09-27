/**
 * Copyright (c) 2015-2016 Bosch Software Innovations GmbH and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * The Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 * Bosch Software Innovations GmbH - Please refer to git log
 */
package org.eclipse.vorto.repository.web.config;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

import javax.servlet.Filter;

import org.springframework.security.core.Authentication;
import org.eclipse.vorto.repository.account.impl.IUserRepository;
import org.eclipse.vorto.repository.account.impl.User;
import org.eclipse.vorto.repository.sso.AuthorizationTokenFilter;
import org.eclipse.vorto.repository.sso.InterceptedUserInfoTokenServices;
import org.eclipse.vorto.repository.sso.boschid.EidpOAuth2RestTemplate;
import org.eclipse.vorto.repository.sso.boschid.EidpResourceDetails;
import org.eclipse.vorto.repository.sso.boschid.JwtTokenUserInfoServices;
import org.eclipse.vorto.repository.web.AngularCsrfHeaderFilter;
import org.eclipse.vorto.repository.web.listeners.AuthenticationEntryPoint;
import org.eclipse.vorto.repository.web.listeners.AuthenticationSuccessHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.CompositeFilter;

@Configuration
@EnableWebSecurity
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
@EnableOAuth2Client
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	   private final Logger LOGGER = LoggerFactory.getLogger(getClass());

	@Autowired
	private IUserRepository userRepository;
	
	 @Autowired
	 public void configureGlobal(AuthenticationManagerBuilder auth)
	       throws Exception {
	     auth
	     .inMemoryAuthentication()
	     .withUser("test").password("test")
	     .authorities("ROLE_USER") .and().withUser("test2").password("test2").roles("USER").and().withUser("test3").password("test3").roles("USER")
	     .and().withUser("admin").password("admin").roles("ADMIN")
	     .and().withUser("user").password("user").roles("USER");
	   }

	
	 
	 @Component("customBasicAuthFilter")
	 public class CustomBasicAuthFilter extends BasicAuthenticationFilter {

		
		private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
		

		 
		 
		 @Autowired
	     public CustomBasicAuthFilter(AuthenticationManager authenticationManager) {
	         super(authenticationManager);
	     }

	     protected void onSuccessfulAuthentication(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, Authentication authResult) throws IOException {
	         // Do what you want here
	 		Authentication auth = authResult;
			
	 		LOGGER.info("onSuccessfulAuthentication"+auth.getName());
	 		
			Optional<User> _user = Optional.ofNullable(userRepository.findByUsername(auth.getName()));
			
	
			
			String targetUrl = _user.map(user -> {
				return "/#/";
			}).orElse("/#/signup");

			if (response.isCommitted()) {
				logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
				return;
			}
			

	 		//String targetUrl = "/#/";
	 		
			redirectStrategy.sendRedirect(request, response, targetUrl);
	    	 
	    	 
	     }
	 }
	 
	//private  CustomBasicAuthFilter customBasicAuthFilter;
	 
	 
	@Autowired
	private AuthenticationEntryPoint authenticationEntryPoint;
	
	@Autowired
	private AuthenticationSuccessHandler successHandler;
	
	@Autowired
	private OAuth2ClientContext oauth2ClientContext;
	
	@Autowired
	private EidpResourceDetails eidp;
	
	@Autowired
	private AuthorizationCodeResourceDetails github;
	
	@Autowired
	private AccessTokenProvider accessTokenProvider;
	
	@Autowired
	private InterceptedUserInfoTokenServices interceptedUserInfoTokenServices;
	
	@Autowired
	private AuthoritiesExtractor authoritiesExtractor;
	
	
	
	
	
  @Override
   protected void configure(HttpSecurity http) throws Exception {
      http
      .authorizeRequests()
      .anyRequest().authenticated()
      .antMatchers(HttpMethod.GET, "infomodelrepository").permitAll()
      .antMatchers(HttpMethod.GET, "/rest/**","/api/**").permitAll()
	   .antMatchers("/user/**").permitAll()
	   .antMatchers(HttpMethod.PUT, "/rest/**","/api/**").permitAll()
	   .antMatchers(HttpMethod.POST, "/rest/**","/api/**").authenticated()
	   .antMatchers(HttpMethod.DELETE, "/rest/**","/api/**").authenticated()
		
	   .and()
		.addFilterAfter(new AngularCsrfHeaderFilter(), CsrfFilter.class)
		.csrf()
		.csrfTokenRepository(csrfTokenRepository())
		
		.and()
		.csrf()
			.disable()
		.logout()
			.logoutUrl("/logout")
			.logoutSuccessUrl("/")
		
      .and()
      .httpBasic()
      .realmName("Your App");
      
     // http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);
      
    }

	
	/*

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.httpBasic()
			.and()
				.authorizeRequests()
				.anyRequest().authenticated()
				.antMatchers(HttpMethod.GET, "/rest/**","/api/**").permitAll()
				.antMatchers("/user/**").permitAll()
				.antMatchers(HttpMethod.PUT, "/rest/**","/api/**").permitAll()
				.antMatchers(HttpMethod.POST, "/rest/**","/api/**").authenticated()
				.antMatchers(HttpMethod.DELETE, "/rest/**","/api/**").authenticated()
			.and()
				.addFilterAfter(new AngularCsrfHeaderFilter(), CsrfFilter.class)
				.addFilter(new CustomBasicAuthFilter(this.authenticationManager()))
				.addFilterAfter(bearerTokenFilter(), SecurityContextPersistenceFilter.class)
				.csrf()
					.csrfTokenRepository(csrfTokenRepository())
			.and()
				.csrf()
					.disable()
				.logout()
					.logoutUrl("/logout")
					.logoutSuccessUrl("/")
			.and()
				.headers()
					.frameOptions()
					.sameOrigin()
					.httpStrictTransportSecurity()
					.disable();
		http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);
	}
	
*/
	
	@Bean
	public static PasswordEncoder encoder() {
		return new BCryptPasswordEncoder(11);
	}
	
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
	private CsrfTokenRepository csrfTokenRepository() {
		HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
		repository.setHeaderName("X-XSRF-TOKEN");
		return repository;
	}
	
	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(
	    OAuth2ClientContextFilter filter) {
	  FilterRegistrationBean registration = new FilterRegistrationBean();
	  registration.setFilter(filter);
	  registration.setOrder(-100);
	  return registration;
	}
	
	private Filter bearerTokenFilter() {
		return new AuthorizationTokenFilter(interceptedUserInfoTokenServices);
	}
	
	private Filter ssoFilter() {
		CompositeFilter filter = new CompositeFilter();
		filter.setFilters(Arrays.asList(githubFilter(), eidpFilter()));
		
		//CustomBasicAuthFilter filter = CustomBasicAuthFilter(
	
		
		return filter;
	}
	
	private Filter githubFilter() {
		return newSsoFilter("/github/login", interceptedUserInfoTokenServices, accessTokenProvider, 
				new OAuth2RestTemplate(github, oauth2ClientContext));		
	}
	
	private Filter eidpFilter() {
		UserInfoTokenServices tokenService = new JwtTokenUserInfoServices("https://accounts.bosch.com/adfs/userinfo", eidp.getClientId());
		return newSsoFilter("/eidp/login", tokenService, accessTokenProvider, 
				new EidpOAuth2RestTemplate(eidp, oauth2ClientContext));
	}
	
	private Filter newSsoFilter(String defaultFilterProcessesUrl, UserInfoTokenServices tokenService, AccessTokenProvider accessTokenProvider,
			OAuth2RestTemplate restTemplate) {
		restTemplate.setAccessTokenProvider(accessTokenProvider);
		
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(defaultFilterProcessesUrl);
		filter.setAuthenticationSuccessHandler(successHandler);
		tokenService.setRestTemplate(restTemplate);
		tokenService.setAuthoritiesExtractor(authoritiesExtractor);
		filter.setRestTemplate(restTemplate);
		filter.setTokenServices(tokenService);
		
		return filter;
	}
	
	@Bean
	@ConfigurationProperties("eidp.oauth2.client")
	public EidpResourceDetails eidp() {
		return new EidpResourceDetails();
	}
	
	@Bean
	@ConfigurationProperties("github.oauth2.client")
	public AuthorizationCodeResourceDetails github() {
		return new AuthorizationCodeResourceDetails();
	}
}