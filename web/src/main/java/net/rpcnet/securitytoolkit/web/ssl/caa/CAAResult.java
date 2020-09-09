package net.rpcnet.securitytoolkit.web.ssl.caa;

import org.immutables.value.Value;

import java.util.Collection;
import java.util.Optional;

@Value.Immutable
public interface CAAResult {
    Optional<String> getTag();
    Optional<String> getValue();
    Optional<String> getFlags();
}
