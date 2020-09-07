package net.rpcnet.securitytoolkit.web.url;

import org.immutables.value.Value;

import java.util.Collection;

@Value.Immutable
public interface ExtendResult {
    boolean isSuccessful();
    String getFinalResult();
    Collection<String> getIntermediateResults();
}
