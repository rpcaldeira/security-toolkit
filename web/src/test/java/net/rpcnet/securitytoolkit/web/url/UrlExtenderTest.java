package net.rpcnet.securitytoolkit.web.url;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.util.Optional;

class UrlExtenderTest {

    @Test
    void testNoRedirection(){
        String shortUrl = "https://github.com/rpcaldeira/security-toolkit";

        ExtendResult extendResult = UrlExtender.extendUrl(shortUrl);
        Assertions.assertFalse(extendResult.isSuccessful());
        Assertions.assertTrue(extendResult.getIntermediateResults().isEmpty());
        Assertions.assertEquals(Optional.empty(), extendResult.getFinalResult());
    }

    @Test
    void testDirectRedirection(){
        String shortUrl = "https://rpcnet.net/security-toolkit";
        String actualUrl = "https://github.com/rpcaldeira/security-toolkit";

        ExtendResult extendResult = UrlExtender.extendUrl(shortUrl);
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

        ExtendResult extendResult = UrlExtender.extendUrl(shortUrl);
        Assertions.assertTrue(extendResult.isSuccessful());
        Assertions.assertEquals(1, extendResult.getIntermediateResults().size());
        Assertions.assertTrue(extendResult.getIntermediateResults().contains(indirectUrl));
        Assertions.assertFalse(extendResult.getFinalResult().isEmpty());
        Assertions.assertEquals(actualUrl, extendResult.getFinalResult().get());
    }

}