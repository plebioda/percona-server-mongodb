/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2025-present Percona and/or its affiliates. All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the Server Side Public License, version 1,
    as published by MongoDB, Inc.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Server Side Public License for more details.

    You should have received a copy of the Server Side Public License
    along with this program. If not, see
    <http://www.mongodb.com/licensing/server-side-public-license>.

    As a special exception, the copyright holders give permission to link the
    code of portions of this program with the OpenSSL library under certain
    conditions as described in each individual source file and distribute
    linked combinations including the program with the OpenSSL library. You
    must comply with the Server Side Public License in all respects for
    all of the code used other than as permitted herein. If you modify file(s)
    with this exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do so,
    delete this exception statement from your version. If you delete this
    exception statement from all source files in the program, then also delete
    it in the license file.
======= */

#pragma once

#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"
#include "mongo/util/periodic_runner.h"
#include <boost/optional.hpp>
#include <memory>
#include <ranges>

namespace mongo {

class ServiceContext;

namespace crypto {
class JWKManager;
};

/**
 * Registry of all configured OIDC identity providers.
 */
class OidcIdentityProvidersRegistry {
public:
    // Instantiates the registry and registers it with the service context.
    static void init(ServiceContext* service);

    // Returns the registry instance from service context decoration.
    static OidcIdentityProvidersRegistry& get(ServiceContext* service);

    // Sets the registry instance in service context decoration.
    static void set(ServiceContext* service,
                    std::unique_ptr<OidcIdentityProvidersRegistry> registry);

    explicit OidcIdentityProvidersRegistry(PeriodicRunner* periodicRunner,
                                           const std::vector<OidcIdentityProviderConfig>& configs);

    // Returns the OIDC identity provider configuration for the given issuer and audience.
    boost::optional<const OidcIdentityProviderConfig&> getIdp(
        const std::string& issuer, const std::vector<std::string>& audience) const;

    // Returns the OIDC identity provider configuration for the principal name.
    boost::optional<const OidcIdentityProviderConfig&> getIdpForPrincipalName(
        boost::optional<std::string> principalName) const;

    // Returns true if there i at least one identity provider with human flows support.
    bool hasIdpWithHumanFlowsSupport() const {
        return !_hfidps.empty();
    }

    // Returns the number of identity providers with human flows support.
    size_t numOfIdpsWithHumanFlowsSupport() const {
        return _hfidps.size();
    }

    // Returns a JWKManager instance for a given issuer.
    std::shared_ptr<crypto::JWKManager> getJWKManager(const std::string& issuer) const;

private:
    const std::vector<OidcIdentityProviderConfig>& _idps;
    using IdpConfigIterator = std::vector<OidcIdentityProviderConfig>::const_iterator;
    std::ranges::subrange<IdpConfigIterator> _hfidps;
    std::map<std::string, std::shared_ptr<crypto::JWKManager>> _jwkManagers;
    std::vector<PeriodicJobAnchor> _jobs;
};

}  // namespace mongo
