package net.rpcnet.securitytoolkit.web.url;

import org.immutables.value.Value;

import java.util.Collection;
import java.util.Optional;

@Value.Immutable
public interface ExtendResult {
    boolean isSuccessful();
    Optional<String> getFinalResult();
    Collection<String> getIntermediateResults();
}
