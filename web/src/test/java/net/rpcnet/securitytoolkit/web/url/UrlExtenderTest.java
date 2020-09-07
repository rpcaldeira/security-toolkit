package net.rpcnet.securitytoolkit.web.url;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class UrlExtenderTest {

    @Test
    void testBasic(){
        ExtendResult extendResult = UrlExtender.extendUrl("http://tinyurl.com/KindleWireless");
        Assertions.assertTrue(extendResult.isSuccessful());
    }

}