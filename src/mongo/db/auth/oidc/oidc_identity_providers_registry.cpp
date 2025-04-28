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

#include "mongo/db/auth/oidc/oidc_identity_providers_registry.h"
#include "mongo/crypto/jwk_manager.h"
#include "mongo/crypto/jwks_fetcher_impl.h"
#include "mongo/db/service_context.h"
#include "mongo/util/assert_util_core.h"
#include "mongo/util/periodic_runner.h"
#include <memory>

#include "mongo/logv2/log.h"
#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kDefault

namespace mongo {

namespace {
// Returns the list of OIDC identity provider configurations from the server parameters.
const std::vector<OidcIdentityProviderConfig>& getIdPConfigs() {
    return ServerParameterSet::getNodeParameterSet()
        ->get<OidcIdentityProvidersServerParameter>("oidcIdentityProviders")
        ->_data;
}

// Docoration for the OIDC identity providers registry in the service context.
const auto getOidcIdentityProvidersRegistry =
    ServiceContext::declareDecoration<std::unique_ptr<OidcIdentityProvidersRegistry>>();
}  // namespace

void OidcIdentityProvidersRegistry::init(ServiceContext* serviceContext) {
    invariant(serviceContext->getPeriodicRunner());

    OidcIdentityProvidersRegistry::set(serviceContext,
                                       std::make_unique<OidcIdentityProvidersRegistry>(
                                           serviceContext->getPeriodicRunner(), getIdPConfigs()));
}

OidcIdentityProvidersRegistry& OidcIdentityProvidersRegistry::get(ServiceContext* service) {
    auto& uptr = getOidcIdentityProvidersRegistry(service);
    invariant(uptr);
    return *uptr;
}

void OidcIdentityProvidersRegistry::set(ServiceContext* service,
                                        std::unique_ptr<OidcIdentityProvidersRegistry> registry) {
    getOidcIdentityProvidersRegistry(service) = std::move(registry);
}

OidcIdentityProvidersRegistry::OidcIdentityProvidersRegistry(
    PeriodicRunner* periodicRunner, const std::vector<OidcIdentityProviderConfig>& configs)
    : _idps(configs) {

    // `_hfidps` stands for configurations of the identity providers that support human flows.
    // The correctness of the code below stems from the fact that server parameters validation
    // (@see the `src/mongo/db/auth/oidc/oidc_server_parameters.cpp` file) ensures that the
    // configurations of all identity providers that support human flows are listed _before_ those
    // without such support.
    _hfidps = {_idps.begin(), std::ranges::find_if_not(_idps, [](const auto& idp) {
                   return idp.getSupportsHumanFlows();
               })};

    for (const auto& idp : _idps) {
        // create a JWKManager instance for each issuer
        auto res =
            _jwkManagers.emplace(idp.getIssuer(),
                                 std::make_shared<crypto::JWKManager>(
                                     std::make_unique<crypto::JWKSFetcherImpl>(idp.getIssuer())));

        // Skip the periodic job creation if the issuer is already present in the map or the
        // JWKSPollSecs is not configured.
        if (!res.second || idp.getJWKSPollSecs() <= 0) {
            continue;
        }


        // Create and start a periodic job which polls the JWKs from the issuer.
        const auto period = Milliseconds{Seconds(idp.getJWKSPollSecs())};
        auto job = [issuer = res.first->first, jwkManager = res.first->second](Client* client) {
            Status status = jwkManager->loadKeys();
            if (!status.isOK()) {
                LOGV2_WARNING(29140,
                              "Failed to load JWKs from issuer",
                              "issuer"_attr = issuer,
                              "error"_attr = status);
            }
        };

        _jobs.emplace_back(periodicRunner->makeJob(
            PeriodicRunner::PeriodicJob("JWKSPollingJob",
                                        std::move(job),
                                        period,
                                        /* isKillableByStepdown = */ false)));
        _jobs.back().start();
    }
}

boost::optional<const OidcIdentityProviderConfig&> OidcIdentityProvidersRegistry::getIdp(
    const std::string& issuer, const std::vector<std::string>& audience) const {

    // Iterate over the identity providers and check if the issuer matches the identity provider's
    // configuration and if the audience is in the list of given audiences.
    std::set<std::string> audienceSet{audience.begin(), audience.end()};
    auto idp{std::ranges::find_if(_idps, [&](const auto& idp) {
        return std::string_view{idp.getIssuer()} == issuer &&
            audienceSet.contains(std::string{idp.getAudience()});
    })};

    if (idp != _idps.end()) {
        return *idp;
    }
    return boost::none;
}

boost::optional<const OidcIdentityProviderConfig&>
OidcIdentityProvidersRegistry::getIdpForPrincipalName(
    boost::optional<std::string> principalName) const {

    // Iterate over the identity providers that support human flows and check if
    // the principal name matches the match pattern of the identity provider.
    // If the principal name is not provided, return the first identity provider
    // that supports human flows.
    // If the principal name is provided, return the first identity provider
    // that matches the principal name, or the first identity provider that
    // has no match pattern. The server parameters validation ensures that
    // the identity providers without match pattern are listed after those
    // with match pattern.
    // (@see the `src/mongo/db/auth/oidc/oidc_server_parameters.cpp` file for details)
    for (const auto& idp : _hfidps) {
        if (const boost::optional<mongo::MatchPattern>& pattern{idp.getMatchPattern()};
            !principalName || !pattern ||
            std::regex_search(principalName->begin(), principalName->end(), pattern->toRegex())) {

            return idp;
        }
    }

    return boost::none;
}

// Once the '_jwkManagers' map is created in constructor it never changes, so this
// function can be considered thread-safe.
std::shared_ptr<crypto::JWKManager> OidcIdentityProvidersRegistry::getJWKManager(
    const std::string& issuer) const {
    auto it = _jwkManagers.find(issuer);
    if (it != _jwkManagers.end()) {
        return it->second;
    }

    return {};
}

}  // namespace mongo
