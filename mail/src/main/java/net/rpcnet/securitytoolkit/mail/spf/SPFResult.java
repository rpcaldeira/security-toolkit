package net.rpcnet.securitytoolkit.mail.spf;

import org.immutables.value.Value;

import java.util.List;
import java.util.Optional;

@Value.Immutable
public interface SPFResult {

    Optional<Integer> getVersion();
    Optional<SPFQualifier> getMailExchange();
    List<SPFElement> getARecord();
    Optional<SPFQualifier> getAll();
    List<SPFElement> getInclude();

}
