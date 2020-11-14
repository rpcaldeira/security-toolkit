package net.rpcnet.securitytoolkit.web.url;

public class UrlExtender {

    private IHttpClientWrapper httpClientWrapper;

    public UrlExtender(){
        httpClientWrapper = new HttpClientWrapper();
    }

    UrlExtender(IHttpClientWrapper httpClientWrapper){
        this.httpClientWrapper = httpClientWrapper;
    }

    public ExtendResult extendUrl(String shortUrl){
        return httpClientWrapper.extendUrl(shortUrl);
    }

}