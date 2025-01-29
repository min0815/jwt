package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// '/login'으로 요청해서 username, password 전송하면(post) 이 필터가 동작
// formLogin disable해서 현재 작동 안하는 상태 -> addFilter로 필터 추가

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도 중");

        // 1. username, password 받아서
        ObjectMapper om = new ObjectMapper();
        User user = null;
        try {
            user = om.readValue(request.getInputStream(), User.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println(user);

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

        // PrincipalDetailsService의 loadUserByUsername() 함수가 실행되고
        // 정상이면 authentication이 리턴됨
        Authentication authentication
                = authenticationManager.authenticate(authenticationToken);

        // 실행되면 로그인이 되었다는 뜻
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println(principalDetails.getUsername());
        System.out.println("================================");

        // authentication객체가 session 영역에 저장을 해야하고 그 방법이 return 해줌
        // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 거임
        // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리 때문에 session 넣어 줌

        return authentication;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수 실행
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT토큰을 response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨: 인증이 완료됐다는 뜻임");

        // 이 정보로 토큰 생성
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA 방식은 아니구 Hash 암호 방식
        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer " + jwtToken);

        // 아이디, 패스워드가 정상이어서 로그인이 된다면
        // 서버에서 세션ID 생성, 클라이언트 쿠키 세션ID를 응답
        // 요청할 때 마다 쿠키값 세션ID를 항상 들고 서버쪽으로 요청을 하기 때문에 서버는 세션ID가 유효한지 판단후
        // session.getAttribute("세션값 확인"); 유효하면 인증 페이지 접근 허용

        // 하지만 JWT 방식은 아이디, 패스워드가 정상이어서 로그인이 되면
        // 세션ID도 만들지 않고 쿠키도 만들지 않음
        // JWT 토큰을 생성해서 클라이언트 쪽으로 JWT 토큰을 응답,
        // 클라이언트는 요청할 때 마다 JWT 토큰을 가지고 요청, 서버는 JWT 토큰이 유효한지를 판단(판단하는 필터 생성)
    }
}
