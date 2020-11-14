package net.rpcnet.securitytoolkit.web.url;

import net.rpcnet.securitytoolkit.web.url.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

public class HttpClientWrapper implements IHttpClientWrapper{

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpClientWrapper.class);

    private static final String EXTEND_URL_ITERATION_URL = "Iteration URL: {}";

    public ExtendResult extendUrl(String shortUrl){
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
        intermediateResults.remove(shortUrl);

        boolean isSuccessful = !iterationUrl.equals(shortUrl);

        ImmutableExtendResult.Builder builder = ImmutableExtendResult.builder();
        builder.isSuccessful(isSuccessful);

        if(isSuccessful){
            builder.finalResult(Optional.of(iterationUrl));
            builder.intermediateResults(intermediateResults);
        } else {
            builder.finalResult(Optional.empty());
            builder.intermediateResults(Collections.emptyList());
        }

        return builder.build();
    }

}