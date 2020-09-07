package net.rpcnet.securitytoolkit.web.url.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static java.net.HttpURLConnection.HTTP_MOVED_PERM;

public class Utils {

    public static final String HTTP_LOCATION_HEADER_NAME = "location";

    private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);
    private static final String EXTEND_ITERATION_ERROR_EXTENDING_URL = "Error extending URL";
    private static final String EXTEND_ITERATION_FINISHED_EXTENDING_URL_STATUS_CODE = "Finished extending URL, status code {}";
    private static final String EXTEND_ITERATION_ERROR_EXTENDING_URL_RECEIVED_NULL_RESPONSE_FROM_CLIENT = "Error extending URL: Received null response from client";

    private Utils(){
        //Private utility class constructor
    }

    public static String extendIteration(HttpClient client, String url) {
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).build();
        HttpResponse<String> response = null;

        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            LOGGER.error(EXTEND_ITERATION_ERROR_EXTENDING_URL, e);
        } catch (InterruptedException e) {
            LOGGER.error(EXTEND_ITERATION_ERROR_EXTENDING_URL, e);
            Thread.currentThread().interrupt();
        }

        if(response != null && response.statusCode() == HTTP_MOVED_PERM) {
            return response.headers().firstValue(HTTP_LOCATION_HEADER_NAME).orElse(null);
        } else if(response != null){
            LOGGER.debug(EXTEND_ITERATION_FINISHED_EXTENDING_URL_STATUS_CODE, response.statusCode());
            return null;
        }

        LOGGER.error(EXTEND_ITERATION_ERROR_EXTENDING_URL_RECEIVED_NULL_RESPONSE_FROM_CLIENT);
        return null;
    }

}
