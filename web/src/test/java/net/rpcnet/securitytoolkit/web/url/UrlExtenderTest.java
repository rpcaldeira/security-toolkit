package net.rpcnet.securitytoolkit.web.url;

import net.rpcnet.securitytoolkit.common.dns.interfaces.CAADto;
import net.rpcnet.securitytoolkit.common.dns.interfaces.ImmutableCAADto;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UrlExtenderTest {

    private UrlExtender urlExtender;

    @BeforeAll
    public void setUp(){
        IHttpClientWrapper httpClientWrapper = mock(IHttpClientWrapper.class);

        when(httpClientWrapper.extendUrl("https://github.com/rpcaldeira/security-toolkit"))
                .thenReturn(ImmutableExtendResult.builder().isSuccessful(false).finalResult(Optional.empty()).intermediateResults(Collections.emptyList()).build());

        when(httpClientWrapper.extendUrl("https://rpcnet.net/security-toolkit"))
                .thenReturn(ImmutableExtendResult.builder().isSuccessful(true).finalResult(Optional.of("https://github.com/rpcaldeira/security-toolkit")).intermediateResults(Collections.emptyList()).build());

        when(httpClientWrapper.extendUrl("https://tinyurl.com/security-toolkit"))
                .thenReturn(ImmutableExtendResult.builder().isSuccessful(true).finalResult(Optional.of("https://github.com/rpcaldeira/security-toolkit")).intermediateResults(Collections.singletonList("https://rpcnet.net/security-toolkit")).build());

        urlExtender = new UrlExtender(httpClientWrapper);
    }

    @Test
    void testNoRedirection(){
        String shortUrl = "https://github.com/rpcaldeira/security-toolkit";

        ExtendResult extendResult = urlExtender.extendUrl(shortUrl);
        Assertions.assertFalse(extendResult.isSuccessful());
        Assertions.assertTrue(extendResult.getIntermediateResults().isEmpty());
        Assertions.assertEquals(Optional.empty(), extendResult.getFinalResult());
    }

    @Test
    void testDirectRedirection(){
        String shortUrl = "https://rpcnet.net/security-toolkit";
        String actualUrl = "https://github.com/rpcaldeira/security-toolkit";

        ExtendResult extendResult = urlExtender.extendUrl(shortUrl);
        Assertions.assertTrue(extendResult.isSuccessful());
        Assertions.assertTrue(extendResult.getIntermediateResults().isEmpty());
        Assertions.assertFalse(extendResult.getFinalResult().isEmpty());
        Assertions.assertEquals(extendResult.getFinalResult().get(), actualUrl);
    }

    @Test
    void testInDirectRedirection(){
        String shortUrl = "https://tinyurl.com/security-toolkit";
        String indirectUrl = "https://rpcnet.net/security-toolkit";
        String actualUrl = "https://github.com/rpcaldeira/security-toolkit";

        ExtendResult extendResult = urlExtender.extendUrl(shortUrl);
        Assertions.assertTrue(extendResult.isSuccessful());
        Assertions.assertEquals(1, extendResult.getIntermediateResults().size());
        Assertions.assertTrue(extendResult.getIntermediateResults().contains(indirectUrl));
        Assertions.assertFalse(extendResult.getFinalResult().isEmpty());
        Assertions.assertEquals(actualUrl, extendResult.getFinalResult().get());
    }

}