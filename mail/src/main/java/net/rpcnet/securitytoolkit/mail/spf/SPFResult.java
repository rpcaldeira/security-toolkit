package net.rpcnet.securitytoolkit.mail.spf;

import org.immutables.value.Value;

import java.util.List;
import java.util.Optional;

@Value.Immutable
public interface SPFResult {

    Optional<String> getVersion();
    Optional<String> getMailExchange();
    Optional<String> getARecord();
    Optional<String> getAll();
    List<String> getInclude();

}
