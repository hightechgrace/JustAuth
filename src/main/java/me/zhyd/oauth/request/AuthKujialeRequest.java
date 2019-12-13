package me.zhyd.oauth.request;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import com.alibaba.fastjson.JSONObject;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.StringUtils;
import me.zhyd.oauth.utils.UrlBuilder;

import java.util.function.Function;

/**
 * 酷家乐授权登录
 *
 * @author shahuang
 * @since 1.11.0
 */
public class AuthKujialeRequest extends AuthDefaultRequest {

    public AuthKujialeRequest(AuthConfig config) {
        super(config, AuthDefaultSource.KUJIALE);
    }

    public AuthKujialeRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.KUJIALE, authStateCache);
    }



    @Override
    public String authorize(String state, Function<String, String> redirectUriProcess) {

        return authorize(state, "get_user_info", redirectUriProcess);
    }

    /**
     * 请求授权url
     *
     * @param state    state 验证授权流程的参数，可以防止csrf
     * @param scopeStr 请求用户授权时向用户显示的可进行授权的列表。如果要填写多个接口名称，请用逗号隔开
     *                 参考https://open.kujiale.com/open/apps/2/docs?doc_id=95#Step1%EF%BC%9A%E8%8E%B7%E5%8F%96Authorization%20Code参数表内的scope字段
     * @return authorize url
     */
    public String authorize(String state, String scopeStr, Function<String, String> redirectUriProcess) {
        UrlBuilder urlBuilder = UrlBuilder.fromBaseUrl(source.authorize())
            .queryParam("response_type", "code")
            .queryParam("client_id", config.getClientId())
            .queryParam("redirect_uri", redirectUriProcess.apply(config.getRedirectUri()))
            .queryParam("state", getRealState(state));
        if (StringUtils.isNotEmpty(scopeStr)) {
            urlBuilder.queryParam("scope", scopeStr);
        }
        return urlBuilder.build();
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback, Function<String, String> redirectUriProcess) {
        HttpResponse response = doPostAuthorizationCode(authCallback.getCode(), redirectUriProcess);
        return getAuthToken(response);
    }

    private AuthToken getAuthToken(HttpResponse response) {
        JSONObject accessTokenObject = checkResponse(response);
        JSONObject resultObject = accessTokenObject.getJSONObject("d");
        return AuthToken.builder()
            .accessToken(resultObject.getString("accessToken"))
            .refreshToken(resultObject.getString("refreshToken"))
            .expireIn(resultObject.getIntValue("expiresIn"))
            .build();
    }

    private JSONObject checkResponse(HttpResponse response) {
        String accessTokenStr = response.body();
        JSONObject accessTokenObject = JSONObject.parseObject(accessTokenStr);
        if (!"0".equals(accessTokenObject.getString("c"))) {
            throw new AuthException(accessTokenObject.getString("m"));
        }
        return accessTokenObject;
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken, Function<String, String> redirectUriProcess) {
        String openId = this.getOpenId(authToken);
        HttpResponse response = HttpRequest.get(UrlBuilder.fromBaseUrl(source.userInfo())
            .queryParam("access_token", authToken.getAccessToken())
            .queryParam("open_id", openId)
            .build()).execute();
        JSONObject object = JSONObject.parseObject(response.body());
        if (!"0".equals(object.getString("c"))) {
            throw new AuthException(object.getString("m"));
        }
        JSONObject resultObject = object.getJSONObject("d");

        return AuthUser.builder()
            .username(resultObject.getString("userName"))
            .nickname(resultObject.getString("userName"))
            .avatar(resultObject.getString("avatar"))
            .uuid(resultObject.getString("openId"))
            .token(authToken)
            .source(source.toString())
            .build();
    }

    /**
     * 获取酷家乐的openId，此id在当前client范围内可以唯一识别授权用户
     *
     * @param authToken 通过{@link AuthKujialeRequest#getAccessToken(AuthCallback, Function<String, String>)}获取到的{@code authToken}
     * @return openId
     */
    private String getOpenId(AuthToken authToken) {
        HttpResponse response = HttpRequest.get(UrlBuilder.fromBaseUrl("https://oauth.kujiale.com/oauth2/auth/user")
            .queryParam("access_token", authToken.getAccessToken())
            .build()).execute();
        JSONObject accessTokenObject = checkResponse(response);
        return accessTokenObject.getString("d");
    }

    @Override
    public AuthResponse refresh(AuthToken authToken, Function<String, String> redirectUriProcess) {
        HttpResponse response = HttpRequest.post(refreshTokenUrl(authToken.getRefreshToken(), redirectUriProcess)).execute();
        return AuthResponse.builder().code(AuthResponseStatus.SUCCESS.getCode()).data(getAuthToken(response)).build();
    }
}
