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

#include "mongo/db/auth/external/sasl_oidc_server_mechanism.h"

#include "mongo/base/error_codes.h"
#include "mongo/bson/bsontypes.h"
#include "mongo/util/assert_util_core.h"
#include <fmt/format.h>
#include <memory>

#include "mongo/bson/bsonobj.h"
#include "mongo/crypto/jws_validated_token.h"
#include "mongo/db/auth/oidc/oidc_identity_providers_registry.h"
#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"
#include "mongo/db/auth/oidc_protocol_gen.h"
#include "mongo/db/auth/sasl_mechanism_registry.h"
#include "mongo/db/server_parameter.h"
#include "mongo/logv2/log.h"
#include "mongo/logv2/log_attr.h"
#include "mongo/util/assert_util.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kAccessControl

namespace mongo {

StatusWith<std::tuple<bool, std::string>> SaslOidcServerMechanism::stepImpl(OperationContext* opCtx,
                                                                            StringData input) {
    if (Status s{validateBSON(input.data(), input.size())}; !s.isOK()) {
        return s;
    }
    BSONObj inputBson{input.data()};
    // Both `OIDCMechanismClientStep1` and `OIDCMechanismClientStep2` are
    // parsed in the non-strict mode, meaning unknown fields are allowed and
    // ignored (@see the `src/mongo/db/auth/oidc_protocol.idl` file).
    // Since `OIDCMechanismClientStep1` has only one optional field `n`,
    // non-strict parsing results in _any_ valid BSON object (including BSON
    // representation of `OIDCMechanismClientStep2`) being successfully
    // parsed into the `OIDCMechanismClientStep1` object, with or without the
    // `n` field. To avoid confusion, we first try to read the input as a
    // `OIDCMechanismClientStep2` object, which is not subject to the just
    // described issue because its only `jwt` field is mandatory.
    try {
        return step2(
            opCtx->getServiceContext(),
            auth::OIDCMechanismClientStep2::parse(IDLParserContext("OIDCStep2Request"), inputBson));
    } catch (const DBException& e) {
        // Failed to parse the input as a step 2 request. It still can be
        // a step 1 request, so suppress the exception.
    }
    try {
        return step1(
            opCtx->getServiceContext(),
            auth::OIDCMechanismClientStep1::parse(IDLParserContext("OIDCStep1Request"), inputBson));
    } catch (const DBException& e) {
        return e.toStatus();
    }
    MONGO_UNREACHABLE;
}

StatusWith<std::tuple<bool, std::string>> SaslOidcServerMechanism::step1(
    ServiceContext* serviceContext, const auth::OIDCMechanismClientStep1& request) {
    _step = 1;

    const auto& oidcIdPRegistry = OidcIdentityProvidersRegistry::get(serviceContext);
    // Check if there is any IdP with 'supportsHumanFlows'. If not, cannot proceed with step1.
    if (!oidcIdPRegistry.hasIdpWithHumanFlowsSupport()) {
        return Status{ErrorCodes::BadValue,
                      "None of configured identity providers support human flows"};
    }

    // Casting boost::optional<StringData> to boost::optional<std::string>
    boost::optional<std::string> principalName{
        request.getPrincipalName()
            ? boost::optional<std::string>{request.getPrincipalName()->toString()}
            : boost::none};

    LOGV2(77012, "OIDC step 1", "principalName"_attr = principalName ? *principalName : "none");

    // If there are more than one IdP with human flows support, the client must provide a principal
    // name to choose a specific IdP. If there is only one IdP with human flows support, the client
    // can omit the principal name and the server will choose the only IdP available.
    if (!principalName && oidcIdPRegistry.numOfIdpsWithHumanFlowsSupport() > 1) {
        return Status{
            ErrorCodes::BadValue,
            "Multiple identity providers are known, provide a principal name for choosing a one"};
    }

    // Choose the IdP configuration for a given principal name.
    // If the principal name is not provided, the server will choose the only IdP available.
    auto idp = oidcIdPRegistry.getIdpForPrincipalName(principalName);
    if (!idp.has_value()) {
        return Status{
            ErrorCodes::BadValue,
            fmt::format("No identity provider found for principal name `{}`", *principalName)};
    }

    // Reply with the 'issuer' and 'clientId' fields of the chosen IdP.
    auth::OIDCMechanismServerStep1 response;
    response.setIssuer(idp->getIssuer());

    // Server parameters validation
    // (@see the `src/mongo/db/auth/oidc/oidc_server_parameters.cpp` file) ensures that
    // a client ID exists for the identity providers supporting human flows.
    invariant(idp->getClientId().has_value());
    response.setClientId(*idp->getClientId());
    BSONObj b{response.toBSON()};
    return std::tuple{false, std::string{b.objdata(), static_cast<std::size_t>(b.objsize())}};
}

StatusWith<std::tuple<bool, std::string>> SaslOidcServerMechanism::step2(
    ServiceContext* serviceContext, const auth::OIDCMechanismClientStep2& request) try {
    _step = 2;

    const auto& oidcIdPRegistry = OidcIdentityProvidersRegistry::get(serviceContext);

    // Parse the JWT and check for required claims, such as 'iss', 'aud', 'sub' and 'exp'.
    // Extract the issuer and audience claims which are essential for further processing of the
    // token.
    const auto issuerAudienceStatus =
        crypto::JWSValidatedToken::extractIssuerAndAudienceFromCompactSerialization(
            request.getJWT());
    uassert(
        ErrorCodes::BadValue,
        fmt::format("Invalid JWT: parsing failed: {}", issuerAudienceStatus.getStatus().reason()),
        issuerAudienceStatus.isOK());

    const auto issuer = issuerAudienceStatus.getValue().issuer;
    const auto audience = issuerAudienceStatus.getValue().audience;

    // Get the IdP configuration for a issuer/audience pair from the token
    auto idp = oidcIdPRegistry.getIdp(issuer, audience);
    uassert(ErrorCodes::BadValue, "Invalid JWT: unsupported issuer or audience", idp.has_value());

    // Get the JWKManager for a given issuer for token validation.
    auto jwkManager = oidcIdPRegistry.getJWKManager(issuerAudienceStatus.getValue().issuer);
    invariant(jwkManager);  // if the issuer is valid, the JWKManager for the issuer must exist

    // Validate the token's signature, as well as 'exp' and 'nbf' claims.
    const crypto::JWSValidatedToken token{jwkManager.get(), std::string{request.getJWT()}};

    // Check if the configured claim for principalName exists and is a string.
    uassert(ErrorCodes::BadValue,
            fmt::format("InvalidJWT: {} '{}' claim is missing",
                        OidcIdentityProviderConfig::kPrincipalNameFieldName,
                        idp->getPrincipalName()),
            token.getBodyBSON().hasField(idp->getPrincipalName()));

    uassert(ErrorCodes::BadValue,
            fmt::format("InvalidJWT: {} '{}' claim format is not string",
                        OidcIdentityProviderConfig::kPrincipalNameFieldName,
                        idp->getPrincipalName()),
            token.getBodyBSON()[idp->getPrincipalName()].type() == BSONType::String);

    std::string authNamePrefix{idp->getAuthNamePrefix()};

    // store _principalName to return it in UserRequest for authorization manager.
    _principalName =
        authNamePrefix + "/" + std::string{token.getBodyBSON()[idp->getPrincipalName()].String()};

    if (idp->getUseAuthorizationClaim()) {
        // Check if configured authorization claim exists, is of correct format and
        // store the roles.
        // The server parameters validation ensures the 'authorizationClaim' fields is
        // present if the 'useAuthorizationClaim=true'
        // (@see the `src/mongo/db/auth/oidc/oidc_server_parameters.cpp` file).
        invariant(idp->getAuthorizationClaim().has_value());
        uassert(ErrorCodes::BadValue,
                fmt::format("InvalidJWT: {} '{}' is missing",
                            OidcIdentityProviderConfig::kAuthorizationClaimFieldName,
                            *idp->getAuthorizationClaim()),
                token.getBodyBSON().hasField(*idp->getAuthorizationClaim()));

        // The '_roles' is an optional set. Constructing an empty set is 'useAuthorizationClaim'
        // is true is essential to distinguish between 'useAuthorizationClaim=false' and
        // 'useAuthorizationClaim=true' when the claim has no roles. This makes a difference
        // in processing the UserRequest by the authorization manager.
        _roles.emplace();

        auto addRole = [&roles = this->_roles, &authNamePrefix](const std::string& claim) {
            roles->emplace(authNamePrefix + "/" + claim, "admin");
        };

        const auto _authClaim = token.getBodyBSON().getField(*idp->getAuthorizationClaim());

        switch (_authClaim.type()) {
            case BSONType::String:
                addRole(_authClaim.String());
                break;
            case BSONType::Array:
                for (const auto& c : _authClaim.Array()) {
                    uassert(ErrorCodes::BadValue,
                            fmt::format("Invalid JWT: {} '{}' value is not a string",
                                        OidcIdentityProviderConfig::kAuthorizationClaimFieldName,
                                        *idp->getAuthorizationClaim()),
                            c.type() == BSONType::String);
                    addRole(c.String());
                }
                break;
            default:
                return Status{
                    ErrorCodes::BadValue,
                    fmt::format("Invalid JWT: {} `{}` is neither a string nor an array of strings",
                                OidcIdentityProviderConfig::kAuthorizationClaimFieldName,
                                *idp->getAuthorizationClaim())};
        }
    }

    LOGV2(77012, "OIDC step 2", "principalName"_attr = _principalName, "roles"_attr = _roles);

    // authentication succeeded
    return std::tuple{true, std::string{}};
} catch (const DBException& e) {
    return e.toStatus();  // TODO: remove? cannot cover this line with tests
}

UserRequest SaslOidcServerMechanism::getUserRequest() const {
    return UserRequest{UserName{getPrincipalName(), getAuthenticationDatabase()}, _roles};
}

namespace {
GlobalSASLMechanismRegisterer<OidcServerFactory> oidcRegisterer;
}  // namespace
}  // namespace mongo
