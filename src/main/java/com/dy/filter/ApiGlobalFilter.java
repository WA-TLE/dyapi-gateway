package com.dy.filter;


import cn.hutool.core.util.StrUtil;
import com.dy.utils.SignUtils;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 全局拦截器
 *
 * @Author: dy
 * @Date: 2024/2/6 20:36
 * @Description:
 */
@Slf4j
@Component
//@Configuration
public class ApiGlobalFilter implements GlobalFilter, Ordered {

    //  定义白名单                                         Arrays.asList("127.0.0.1");
    public static final List<String> IP_WHITE_LIST = List.of("127.0.0.1");


    //  1. 用户发送请求到 API 网关    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        log.info("custom global filter");
        //  2. 请求日志
        //  2.1 获取请求的信息并输出日志
        ServerHttpRequest request = exchange.getRequest();
        log.info("请求头唯一标识: {}", request.getId());
        log.info("请求头信息: {}", request.getHeaders());
        log.info("请求路径 value: {}" + request.getPath().value());
        log.info("请求路径 toString: {}" + request.getPath().toString());
        InetSocketAddress remoteAddress = request.getRemoteAddress();
        String sourceAddress = null;
        if (remoteAddress != null) {
            sourceAddress = remoteAddress.getHostName();
            log.info("请求地址: {}" + sourceAddress);
        }
        MultiValueMap<String, String> queryParams = request.getQueryParams();
        log.info("请求参数: {}", queryParams);


        //  3. （黑白名单）
        //  3.1 关于黑白名单, 我们并没有使用什么高深的做法, 仅仅就是定义后然后拦截
        if (!IP_WHITE_LIST.contains(sourceAddress)) {
            //  3.2 获取响应
            ServerHttpResponse response = exchange.getResponse();
            //  3.3 设置响应状态码 (禁止访问 403)
            response.setStatusCode(HttpStatus.FORBIDDEN);
            //  3.4 返回处理完成后的响应
            return response.setComplete();
        }

        //  4. 用户鉴权（判断 ak、sk 是否合法）
        ServerHttpResponse response = exchange.getResponse();

        //  1. 从请求头中获取 accessKey 和 secretKey 来判断是否为合法调用
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String nonce = headers.getFirst("nonce");
        String timestamp = headers.getFirst("timestamp");
        String sign = headers.getFirst("sign");
        String body = headers.getFirst("body");

        if (StrUtil.hasBlank(accessKey, nonce, timestamp, sign, body)) {
            return handleNoAuth(response);
        }


        // TODO: 2023/12/22  这里应该是从数据库中取 accessKey 和 secretKey 的, 这里先不照做
        if (!accessKey.equals("dingyu")) {
            return handleNoAuth(response);
        }

        //  判断随机数是否重复
        if (Long.parseLong(nonce) > 10000) {
            return handleNoAuth(response);
        }

        //  判断时间是否超时...
        long currentTimeMillis = System.currentTimeMillis() / 1000;
        final Long FIVE_MINUTES = 60 * 5L;
        if ((currentTimeMillis - Long.parseLong(timestamp)) >= FIVE_MINUTES) {
            return handleNoAuth(response);
        }

        // TODO: 2023/12/22 实际是从数据库中查出的 secretKey
        String serverSign = SignUtils.getSign(body, "Hello world");

        if (!sign.equals(serverSign)) {
            return handleNoAuth(response);
        }

        //  5. 请求的模拟接口是否存在？
        //  5.1 这里需要查询数据库, 不建议在网关写
        // TODO: 2024/2/6 远程调用, 查询数据库, 判断接口是否存在

        //  6. **请求转发，调用模拟接口**
        // TODO: 2024/2/6 远程调用, 接口次数加一


//        Mono<Void> filter = chain.filter(exchange);
//        if (response.getStatusCode() == HttpStatus.OK) {
//            //  7. 响应日志
//            //  8. 调用成功，接口调用次数 + 1
//
//
//        } else {
//            return handleInvokeError(response);
//        }

        //  9. 调用失败，返回一个规范的错误码


        return handleResponse(exchange, chain);
    }

    @Override
    public int getOrder() {
        return -1;
    }


    private Mono<Void> handleNoAuth(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    private Mono<Void> handleInvokeError(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }


    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain) {

        try {
            ServerHttpResponse originalResponse = exchange.getResponse();
            // 缓存数据的工厂
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();
            // 拿到响应码
            HttpStatusCode statusCode = originalResponse.getStatusCode();
            if (statusCode == HttpStatus.OK) {
                // 装饰，增强能力
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
                    // 等调用完转发的接口后才会执行
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        log.info("body instanceof Flux: {}", (body instanceof Flux));
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            // 往返回值里写数据
                            // 拼接字符串
                            return super.writeWith(
                                    fluxBody.map(dataBuffer -> {
                                        // 7. todo 调用成功，接口调用次数 + 1 invokeCount
                                        byte[] content = new byte[dataBuffer.readableByteCount()];
                                        dataBuffer.read(content);
                                        DataBufferUtils.release(dataBuffer);//释放掉内存
                                        // 构建日志
                                        StringBuilder sb2 = new StringBuilder(200);
                                        List<Object> rspArgs = new ArrayList<>();
                                        rspArgs.add(originalResponse.getStatusCode());
                                        String data = new String(content, StandardCharsets.UTF_8); //data
                                        sb2.append(data);
                                        // 打印日志
                                        log.info("响应结果：" + data);
                                        return bufferFactory.wrap(content);
                                    }));
                        } else {
                            // 8. 调用失败，返回一个规范的错误码
                            log.error("<--- {} 响应code异常", getStatusCode());
                        }
                        return super.writeWith(body);
                    }
                };
                // 设置 response 对象为装饰过的
                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            return chain.filter(exchange); // 降级处理返回数据
        } catch (Exception e) {
            log.error("网关处理响应异常" + e);
            return chain.filter(exchange);
        }
    }
}
