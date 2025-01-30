package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

// 시큐리티가 가진 필터 중 BasicAuthenticationFilter라는 것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청시 위 필터를 무조건 타게 되어있음
// 만약 권한이 인증이 필요한 주소가 아니면 이 필터를 타지 않음
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // super.doFilterInternal(request, response, chain);
        System.out.println("인증이나 권한이 필요한 주소 요청이 됨");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader: " + jwtHeader);

        // header가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        // JWT 토큰을 검증해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        String username =
                JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();
        
        // JWT 토큰 서명을 통해서 서명이 정상적이면 Authentication 객체를 만들어준다
        if (username != null) {
            User userEntity = userRepository.findByUsername(username);
            System.out.println("userEntity: " + userEntity.getUsername());
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            System.out.println("principalDetails: " + principalDetails.getUsername() + "테스트테스트");
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // 강제로 시큐리티 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("Security Context Authentication: " + SecurityContextHolder.getContext().getAuthentication());
            System.out.println(principalDetails.getUser().getRoles());
            System.out.println(principalDetails.getUser().getRoleList());
        }
        chain.doFilter(request, response);
    }
}
