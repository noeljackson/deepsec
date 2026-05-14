package com.example.proxy;

import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

public class ProxyService {

    public String fetchVulnerable(String url) {
        return new RestTemplate().getForObject(url, String.class);
    }

    public String fetchWebClientVulnerable(String url) {
        return WebClient.create().get().uri(url).retrieve().bodyToMono(String.class).block();
    }

    public String fetchHealthSafe() {
        return "internal:status:ok";
    }

    public String renderName(String name) {
        return "Hello, " + name;
    }
}
