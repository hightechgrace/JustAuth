package me.zhyd.oauth.utils;

@FunctionalInterface
public interface RedirectUriProcessFunction  {

    String apply(String info);
}
