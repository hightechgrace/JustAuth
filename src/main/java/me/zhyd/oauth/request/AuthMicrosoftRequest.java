package me.zhyd.oauth.request;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import com.alibaba.fastjson.JSONObject;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.UrlBuilder;

import java.util.function.Function;

import static me.zhyd.oauth.utils.GlobalAuthUtil.parseQueryToMap;

/**
 * 微软登录
 *
 * @author yangkai.shen (https://xkcoding.com)
 * @since 1.5.0
 */
public class AuthMicrosoftRequest extends AuthDefaultRequest {
    public AuthMicrosoftRequest(AuthConfig config) {
        super(config, AuthDefaultSource.MICROSOFT);
    }

    public AuthMicrosoftRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.MICROSOFT, authStateCache);
    }

    @Override
    protected AuthToken getAccessToken(AuthCallback authCallback, Function<String, String> redirectUriProcess) {
        return getToken(accessTokenUrl(authCallback.getCode(), redirectUriProcess));
    }

    /**
     * 获取token，适用于获取access_token和刷新token
     *
     * @param accessTokenUrl 实际请求token的地址
     * @return token对象
     */
    private AuthToken getToken(String accessTokenUrl) {
        HttpResponse response = HttpRequest.post(accessTokenUrl)
            .header("Host", "https://login.microsoftonline.com")
            .contentType("application/x-www-form-urlencoded")
            .form(parseQueryToMap(accessTokenUrl))
            .execute();
        String accessTokenStr = response.body();
        JSONObject accessTokenObject = JSONObject.parseObject(accessTokenStr);

        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
            .accessToken(accessTokenObject.getString("access_token"))
            .expireIn(accessTokenObject.getIntValue("expires_in"))
            .scope(accessTokenObject.getString("scope"))
            .tokenType(accessTokenObject.getString("token_type"))
            .refreshToken(accessTokenObject.getString("refresh_token"))
            .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JSONObject object) {
        if (object.containsKey("error")) {
            throw new AuthException(object.getString("error_description"));
        }
    }

    @Override
    protected AuthUser getUserInfo(AuthToken authToken, Function<String, String> redirectUriProcess) {
        String token = authToken.getAccessToken();
        String tokenType = authToken.getTokenType();
        String jwt = tokenType + " " + token;
        HttpResponse response = HttpRequest.get(userInfoUrl(authToken)).header("Authorization", jwt).execute();
        String userInfo = response.body();
        JSONObject object = JSONObject.parseObject(userInfo);
        this.checkResponse(object);
        return AuthUser.builder()
            .uuid(object.getString("id"))
            .username(object.getString("userPrincipalName"))
            .nickname(object.getString("displayName"))
            .location(object.getString("officeLocation"))
            .email(object.getString("mail"))
            .gender(AuthUserGender.UNKNOWN)
            .token(authToken)
            .source(source.toString())
            .build();
    }

    /**
     * 刷新access token （续期）
     *
     * @param authToken 登录成功后返回的Token信息
     * @return AuthResponse
     */
    @Override
    public AuthResponse refresh(AuthToken authToken, Function<String, String> redirectUriProcess) {
        return AuthResponse.builder()
            .code(AuthResponseStatus.SUCCESS.getCode())
            .data(getToken(refreshTokenUrl(authToken.getRefreshToken(), redirectUriProcess)))
            .build();
    }



    @Override
    public String authorize(String state, Function<String, String> redirectUriProcess) {

        return UrlBuilder.fromBaseUrl(source.authorize())
            .queryParam("response_type", "code")
            .queryParam("client_id", config.getClientId())
            .queryParam("redirect_uri", redirectUriProcess.apply(config.getRedirectUri()))
            .queryParam("response_mode", "query")
            .queryParam("scope", "offline_access%20user.read%20mail.read")
            .queryParam("state", getRealState(state))
            .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param code 授权code
     * @return 返回获取accessToken的url
     */
    @Override
    protected String accessTokenUrl(String code, Function<String, String> redirectUriProcess) {
        return UrlBuilder.fromBaseUrl(source.accessToken())
            .queryParam("code", code)
            .queryParam("client_id", config.getClientId())
            .queryParam("client_secret", config.getClientSecret())
            .queryParam("grant_type", "authorization_code")
            .queryParam("scope", "user.read%20mail.read")
            .queryParam("redirect_uri", redirectUriProcess.apply(config.getRedirectUri()))
            .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken 用户授权后的token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo()).build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param refreshToken 用户授权后的token
     * @return 返回获取accessToken的url
     */
    @Override
    protected String refreshTokenUrl(String refreshToken, Function<String, String> redirectUriProcess) {
        return UrlBuilder.fromBaseUrl(source.refresh())
            .queryParam("client_id", config.getClientId())
            .queryParam("client_secret", config.getClientSecret())
            .queryParam("refresh_token", refreshToken)
            .queryParam("grant_type", "refresh_token")
            .queryParam("scope", "user.read%20mail.read")
            .queryParam("redirect_uri", redirectUriProcess.apply(config.getRedirectUri()))
            .build();
    }
}
