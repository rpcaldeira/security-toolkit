package net.rpcnet.securitytoolkit.web.url;

import net.rpcnet.securitytoolkit.web.url.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Objects;

public class UrlExtender {

    private static final Logger LOGGER = LoggerFactory.getLogger(UrlExtender.class);

    private static final String EXTEND_URL_ITERATION_URL = "Iteration URL: {}";

    private UrlExtender(){
        //Private utility class constructor
    }

    public static ExtendResult extendUrl(String shortUrl){
        String iterationUrl = shortUrl;
        String iterationResult;
        Collection<String> intermediateResults = new ArrayList<>();
        HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

        do {
            iterationResult = Utils.extendIteration(client, iterationUrl);
            if(Objects.nonNull(iterationResult)) {
                LOGGER.debug(EXTEND_URL_ITERATION_URL, iterationResult);
                intermediateResults.add(iterationUrl);
                iterationUrl = iterationResult;
            }
        } while (Objects.nonNull(iterationResult));

        return ImmutableExtendResult.builder()
                .isSuccessful(!iterationUrl.equals(shortUrl))
                .finalResult(iterationUrl)
                .intermediateResults(intermediateResults)
                .build();
    }



}