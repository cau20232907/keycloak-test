package org.zeropage.keycloakclient;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;
import java.util.Map;

@RestController
public class ExampleController {

    /** jwt 토큰의 전체 내용 보기
     * @param jwt 로그인 토큰
     * @return claims
     */
    @GetMapping("/")
    public Map<String, Object> index(@AuthenticationPrincipal Jwt jwt) {
        return jwt.getClaims();
    }

    /** jwt 토큰에서 role 뽑아내기(회원등급 보기)
     * @param jwt 로그인 토큰
     * @return role 목록
     */
    @GetMapping("/role")
    @SuppressWarnings("unchecked")
    public List<String> getRole(@AuthenticationPrincipal Jwt jwt){
        Map<String, Object> claims = jwt.getClaims();
        Map<String, Object> resourceAccess = (Map<String, Object>) claims.get("resource_access");
        Map<String, Object> account = (Map<String, Object>) resourceAccess.get("account");
        List<String> roles = (List<String>) account.get("roles");
        return roles;
    }

    /** jwt 토큰의 헤더 뽑아내기
     * @param jwt 로그인 토큰
     * @return 헤더 내용
     */
    @GetMapping("/h")
    public Map<String, Object> heads(@AuthenticationPrincipal Jwt jwt) {
        return jwt.getHeaders();
    }

    @GetMapping("/user")
    public Principal index2(HttpServletRequest request) {
        Principal principal = request.getUserPrincipal();
        //can do something with it
        return principal;
    }

    @GetMapping(path = "/unauthenticated")
    public String unauthenticatedRequests() {
        return "This is unauthenticated endpoint";
    }
}