package com.spring.starter.service;

import java.util.ArrayList;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JwtUserDetailsService implements UserDetailsService{

	@Override
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {		
		if("user1".equals(userName)){
			System.out.println("Inside");
			return new User("user1", 
					"$2a$10$4UDmcMOuTcd3JJ6yipWLbuQ2b8Bwh.tx0817uGvMsrgwBeGSKpLGC", new ArrayList<>());
			

		}
		else {
			throw new UsernameNotFoundException("User cannot be found with the user name");
		}
	}

	
	
}
