package toff.novi.eindopdrachttoffshop.config;

import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import java.net.URI;

public class UriHelper {

    public static URI createUri(String resourcePath, String resourceId) {
        return URI.create(ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path("/" + resourcePath + "/" + resourceId)
                .toUriString()
                );
    }
}