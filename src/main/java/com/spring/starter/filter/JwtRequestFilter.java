package com.spring.starter.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.spring.starter.service.JwtUserDetailsService;
import com.spring.starter.util.JwtTokenUtil;

import io.jsonwebtoken.ExpiredJwtException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter{

	@Autowired
	private JwtTokenUtil jwtTokenUtil; 
	
	@Autowired
	private JwtUserDetailsService userDetailsService; 

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		final String requestTokenHeader = request.getHeader("Authorization");
		String userName = null;
		String jwtToken = null;
		
		/**
		 * Get the Token
		 */
		if(requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
			jwtToken = requestTokenHeader.substring(7);
			try {
	 			userName = jwtTokenUtil.getUserNameFromToken(jwtToken);	 			
			}
			catch (IllegalArgumentException e) {
				System.out.println("Unable to get the JWT Token");
			}
			catch (ExpiredJwtException e) {
				System.out.println("JWT Token has expired");
			}
		}
		else {
			logger.warn("JWT Token does not begin with Bearer String");
		}
		
		/**
		 * Validate the token
		 */
		if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
		   UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
		   
		   if(jwtTokenUtil.validateToken(jwtToken, userDetails)) {
			   UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
					   userDetails, null,userDetails.getAuthorities());
			   authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			   
			   SecurityContextHolder.getContext().setAuthentication(authenticationToken);
		   }
		}
		filterChain.doFilter(request, response);
		
	}

}
