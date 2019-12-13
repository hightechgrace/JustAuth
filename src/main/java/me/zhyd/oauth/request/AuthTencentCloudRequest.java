package me.zhyd.oauth.request;

import cn.hutool.http.HttpResponse;
import com.alibaba.fastjson.JSONObject;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.UrlBuilder;

import java.util.function.Function;

/**
 * 腾讯云登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.0.0
 */
public class AuthTencentCloudRequest extends AuthDefaultRequest {

    public AuthTencentCloudRequest(AuthConfig config) {
        super(config, AuthDefaultSource.TENCENT_CLOUD);
    }

    public AuthTencentCloudRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.TENCENT_CLOUD, authStateCache);
    }

    @Override
    protected AuthToken getAccessToken(AuthCallback authCallback, Function<String, String> redirectUriProcess) {
        HttpResponse response = doGetAuthorizationCode(authCallback.getCode(), redirectUriProcess);
        JSONObject accessTokenObject = JSONObject.parseObject(response.body());
        this.checkResponse(accessTokenObject);
        return AuthToken.builder()
            .accessToken(accessTokenObject.getString("access_token"))
            .expireIn(accessTokenObject.getIntValue("expires_in"))
            .refreshToken(accessTokenObject.getString("refresh_token"))
            .build();
    }

    @Override
    protected AuthUser getUserInfo(AuthToken authToken, Function<String, String> redirectUriProcess) {
        HttpResponse response = doGetUserInfo(authToken);
        JSONObject object = JSONObject.parseObject(response.body());
        this.checkResponse(object);

        object = object.getJSONObject("data");
        return AuthUser.builder()
            .uuid(object.getString("id"))
            .username(object.getString("name"))
            .avatar("https://dev.tencent.com/" + object.getString("avatar"))
            .blog("https://dev.tencent.com/" + object.getString("path"))
            .nickname(object.getString("name"))
            .company(object.getString("company"))
            .location(object.getString("location"))
            .gender(AuthUserGender.getRealGender(object.getString("sex")))
            .email(object.getString("email"))
            .remark(object.getString("slogan"))
            .token(authToken)
            .source(source.toString())
            .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JSONObject object) {
        if (object.getIntValue("code") != 0) {
            throw new AuthException(object.getString("msg"));
        }
    }



    @Override
    public String authorize(String state, Function<String, String> redirectUriProcess) {

        return UrlBuilder.fromBaseUrl(source.authorize())
            .queryParam("response_type", "code")
            .queryParam("client_id", config.getClientId())
            .queryParam("redirect_uri", redirectUriProcess.apply(config.getRedirectUri()))
            .queryParam("scope", "user")
            .queryParam("state", getRealState(state))
            .build();
    }
}
