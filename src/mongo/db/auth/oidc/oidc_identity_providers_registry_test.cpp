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

#include "boost/none_t.hpp"
#include "mongo/db/auth/oidc/match_pattern.h"
#include "mongo/db/auth/oidc/oidc_identity_providers_registry.h"
#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"
#include "mongo/unittest/assert.h"
#include "mongo/unittest/framework.h"
#include <type_traits>

namespace mongo {

// comparator for OidcIdentityProviderConfig objects required by ASSERT_EQ and similar macros
bool operator==(const OidcIdentityProviderConfig& lhs, const OidcIdentityProviderConfig& rhs) {
    return lhs.getIssuer() == rhs.getIssuer() && lhs.getAudience() == rhs.getAudience() &&
        lhs.getAuthNamePrefix() == rhs.getAuthNamePrefix() &&
        lhs.getSupportsHumanFlows() == rhs.getSupportsHumanFlows();
}

namespace {

// Base class for OidcIdentityProviderConfig's field setters
class SetField {
public:
    virtual void set(OidcIdentityProviderConfig& config) = 0;
};

// Helper class for storing a value
template <typename T>
class SetFieldWithValue : public SetField {
public:
    explicit SetFieldWithValue(T value) : _value(value) {}

    T getValue() const {
        return _value;
    }

private:
    T _value;
};

// Setter for the 'matchPattern' field
struct SetMatchPattern : public SetFieldWithValue<std::string> {
    using SetFieldWithValue::SetFieldWithValue;

    void set(OidcIdentityProviderConfig& config) override {
        config.setMatchPattern(MatchPattern(getValue()));
    }
};

// Setter for the 'supportsHumanFlows' field
struct SetSupportsHumanFlows : public SetFieldWithValue<bool> {
    using SetFieldWithValue::SetFieldWithValue;

    void set(OidcIdentityProviderConfig& config) override {
        config.setSupportsHumanFlows(getValue());
    }
};

// Setter for the 'JWKSPollSecs' field
struct SetJWKSPollSecs : public SetFieldWithValue<std::int32_t> {
    using SetFieldWithValue::SetFieldWithValue;

    void set(OidcIdentityProviderConfig& config) override {
        config.setJWKSPollSecs(getValue());
    }
};

// Creates an OidcIdentityProviderConfig object with the given required parameters
// and a list of optional field setters.
template <typename... Setters>
OidcIdentityProviderConfig make_config(const std::string& issuer,
                                       const std::string& authNamePrefix,
                                       const std::string& audience,
                                       Setters&&... setters) {
    static_assert((std::conjunction_v<std::is_base_of<SetField, std::decay_t<Setters>>...>),
                  "All setters must inherit from SetField");

    OidcIdentityProviderConfig config;
    config.setIssuer(issuer);
    config.setAuthNamePrefix(authNamePrefix);
    config.setAudience(audience);
    (setters.set(config), ...);
    return config;
}

// Helper function to cast std::string to boost::optional<std::string>
auto make_principal_name(const std::string& name) {
    return boost::optional<std::string>(name);
}

// Mock for PeriodicRunner to control the job execution
// and to verify the job's state.
class PeriodicRunnerMock : public PeriodicRunner {
    class ControllableJobMock : public ControllableJob {
    public:
        explicit ControllableJobMock(PeriodicJob job) : _job(std::move(job)) {}
        void start() override {
            _started = true;
        }

        void pause() override {
            // expect not to be used
            ASSERT(false);
        }

        void resume() override {
            // expect not to be used
            ASSERT(false);
        }

        void stop() override {}

        Milliseconds getPeriod() const override {
            return _job.interval;
        }

        void setPeriod(Milliseconds ms) override {
            _job.interval = ms;
        }

        bool isStarted() const {
            return _started;
        }

    private:
        bool _started{false};
        PeriodicJob _job;
    };

public:
    PeriodicJobAnchor makeJob(PeriodicJob job) override {
        auto handle = std::make_shared<ControllableJobMock>(std::move(job));
        jobs.push_back(handle);
        return PeriodicJobAnchor{std::move(handle)};
    }

    std::vector<std::shared_ptr<ControllableJobMock>> jobs;
};

class OidcIdentityProvidersRegistryTest : public unittest::Test {
protected:
    OidcIdentityProvidersRegistry create_registry(
        const std::vector<OidcIdentityProviderConfig>& configs) {
        return OidcIdentityProvidersRegistry(&_periodicRunnerMock, configs);
    }

    PeriodicRunnerMock _periodicRunnerMock;
};

// Succesfull case for getting the idp by issuer and audience if there is only one idp
// in the registry.
TEST_F(OidcIdentityProvidersRegistryTest, getIdp_SingleIdp_Success) {
    std::vector configs{
        make_config("https://issuer", "prefix", "audience"),
    };

    auto registry = create_registry(configs);

    const auto idp = registry.getIdp("https://issuer", {"audience"});
    ASSERT_TRUE(idp.has_value());
    ASSERT_EQ(idp.value(), configs[0]);
}

// Failure case for getting the idp by issuer and audience if there is only one idp
// in the registry.
TEST_F(OidcIdentityProvidersRegistryTest, getIdp_SingleIdp_Failure) {
    std::vector configs{
        make_config("https://issuer", "prefix", "audience"),
    };

    auto registry = create_registry(configs);

    ASSERT_FALSE(registry.getIdp("https://some_issuer", {"audience"}).has_value());
    ASSERT_FALSE(registry.getIdp("https://issuer", {"some_audience"}).has_value());
}

// Succesfull cases for getting the idp by issuer and audience if there are multiple idps
// in the registry.
TEST_F(OidcIdentityProvidersRegistryTest, getIdp_MultipleIdps_Success) {
    std::vector configs{
        make_config("https://issuer", "prefix", "audience"),
        make_config("https://some_issuer", "prefix", "some_audience"),
        make_config("https://another_issuer", "prefix", "another_audience"),
    };

    auto registry = create_registry(configs);

    {
        const auto idp = registry.getIdp("https://issuer", {"audience"});
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        const auto idp = registry.getIdp("https://some_issuer", {"some_audience"});
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[1]);
    }
    {
        const auto idp = registry.getIdp("https://another_issuer", {"another_audience"});
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[2]);
    }
}

// Succesfull case for getting the idp by issuer and vector of audiences if there is
// only one idp in the registry.
TEST_F(OidcIdentityProvidersRegistryTest, getIdp_MultipleAudiences_Success) {
    std::vector configs{
        make_config("https://issuer", "prefix", "audience"),
    };

    auto registry = create_registry(configs);

    const auto idp = registry.getIdp("https://issuer", {"audience1", "audience2", "audience"});
    ASSERT_TRUE(idp.has_value());
    ASSERT_EQ(idp.value(), configs[0]);
}

// Failure case for getting the idp by issuer and audience if there are multiple idps
// in the registry.
TEST_F(OidcIdentityProvidersRegistryTest, getIdp__MultipleIdps_Failure) {
    std::vector configs{
        make_config("https://issuer", "prefix", "audience"),
        make_config("https://some_issuer", "prefix", "some_audience"),
    };

    auto registry = create_registry(configs);

    ASSERT_FALSE(registry.getIdp("https://some_issuer", {"some_audience1"}).has_value());
    ASSERT_FALSE(registry.getIdp("https://issuer", {"some_audience"}).has_value());
    ASSERT_FALSE(registry.getIdp("https://some_issuer", {"audience"}).has_value());
    ASSERT_FALSE(registry.getIdp("https://issuer", {"some_audience1", "audienceX", "some_audience"})
                     .has_value());
    ASSERT_FALSE(
        registry.getIdp("https://some_issuer", {"audience", "some_audience1"}).has_value());
}

// Test for getting the idp by issuer and audience if there are multiple idps
// with the same issuer but different audiences in the registry.
TEST_F(OidcIdentityProvidersRegistryTest, getIdp_OneIssuerMultipleAudiences) {
    std::vector configs{
        make_config("https://issuer", "prefix", "audience1"),
        make_config("https://issuer", "prefix", "audience2"),
        make_config("https://issuer", "prefix", "audience3"),
    };

    auto registry = create_registry(configs);

    ASSERT_FALSE(registry.getIdp("https://issuer", {"audience"}).has_value());

    {
        const auto idp = registry.getIdp("https://issuer", {"audience1"});
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        const auto idp = registry.getIdp("https://issuer", {"audience2"});
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[1]);
    }
    {
        const auto idp = registry.getIdp("https://issuer", {"audience3"});
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[2]);
    }
}

// Succesfull cases for getting the idp by principal name if there are multiple idps
// in the registry and non of them has the match pattern.
TEST_F(OidcIdentityProvidersRegistryTest, getIdpForPrincipalName_AllWithoutMatchPattern_Success) {
    std::vector configs{
        make_config("https://issuer1", "prefix1", "audience1"),
        make_config("https://issuer2", "prefix2", "audience2"),
    };

    auto registry = create_registry(configs);

    {
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("user1"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }

    {
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("user2"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }

    {
        const auto idp = registry.getIdpForPrincipalName(boost::none);
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
}

// Succesfull case for getting the idp by principal name if there are multiple idps
// in the registry and all of them have the match pattern.
TEST_F(OidcIdentityProvidersRegistryTest, getIdpForPrincipalName_AllWithMatchPattern_Success) {
    std::vector configs{
        make_config("https://issuer1", "prefix1", "audience1", SetMatchPattern("1$")),
        make_config("https://issuer2", "prefix2", "audience2", SetMatchPattern("2$")),
    };

    auto registry = create_registry(configs);

    {
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("user1"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }

    {
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("user2"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[1]);
    }

    {
        const auto idp = registry.getIdpForPrincipalName(boost::none);
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
}

// Failure case for getting the idp by principal name if there are multiple idps
// in the registry and all of them have the match pattern.
TEST_F(OidcIdentityProvidersRegistryTest, getIdpForPrincipalName_AllWithMatchPattern_Failure) {
    std::vector configs{
        make_config("https://issuer1", "prefix1", "audience1", SetMatchPattern("1$")),
        make_config("https://issuer2", "prefix2", "audience2", SetMatchPattern("2$")),
    };

    auto registry = create_registry(configs);

    ASSERT_FALSE(registry.getIdpForPrincipalName(make_principal_name("user3")).has_value());
    ASSERT_FALSE(registry.getIdpForPrincipalName(make_principal_name("1user")).has_value());
    ASSERT_FALSE(registry.getIdpForPrincipalName(make_principal_name("2user")).has_value());
}

// Test for getting the idp by principal name if there are multiple idps
// in the registry and none of them supports human flows.
TEST_F(OidcIdentityProvidersRegistryTest, getIdpForPrincipalName_NoneWithSupportHumanFlows) {
    std::vector configs{
        make_config("https://issuer1",
                    "prefix1",
                    "audience1",
                    SetSupportsHumanFlows(false),
                    SetMatchPattern("1$")),
        make_config("https://issuer2",
                    "prefix2",
                    "audience2",
                    SetSupportsHumanFlows(false),
                    SetMatchPattern("2$")),
    };

    auto registry = create_registry(configs);

    ASSERT_FALSE(registry.hasIdpWithHumanFlowsSupport());
    ASSERT_EQ(registry.numOfIdpsWithHumanFlowsSupport(), 0);

    // No idp supports human flows, expect no idp config to be returned
    {
        const auto idp = registry.getIdpForPrincipalName(boost::none);
        ASSERT_FALSE(idp.has_value());
    }
    {
        const auto idp = registry.getIdpForPrincipalName(boost::none);
        ASSERT_FALSE(idp.has_value());
    }
    {
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("user1"));
        ASSERT_FALSE(idp.has_value());
    }
    {
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("user2"));
        ASSERT_FALSE(idp.has_value());
    }
}

// Test for getting the idp by principal name if there are multiple idps
// in the registry and only one of them supports human flows.
TEST_F(OidcIdentityProvidersRegistryTest, getIdpForPrincipalName_OneWithSupportHumanFlows) {
    std::vector configs{
        make_config("https://issuer1", "prefix1", "audience1", SetSupportsHumanFlows(true)),
        make_config("https://issuer2",
                    "prefix2",
                    "audience2",
                    SetSupportsHumanFlows(false),
                    SetMatchPattern("2$")),
    };

    auto registry = create_registry(configs);

    ASSERT_TRUE(registry.hasIdpWithHumanFlowsSupport());
    ASSERT_EQ(registry.numOfIdpsWithHumanFlowsSupport(), 1);

    {
        // Expect first idp if no principal name provided
        const auto idp = registry.getIdpForPrincipalName(boost::none);
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        // Expect first since only first idp supports human flows
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("user1"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        // Expect first since only first idp supports human flows
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("user2"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
}

// Test for getting the idp by principal name if there are multiple idps
// in the registry, all of them have the match pattern and the last one
// matches all principal names.
TEST_F(OidcIdentityProvidersRegistryTest,
       getIdpForPrincipalName_MultipleMatchPatters_LastMathingAll) {
    std::vector configs{
        make_config("https://issuer1", "prefix1", "audience1", SetMatchPattern("1$")),
        make_config("https://issuer2", "prefix2", "audience2", SetMatchPattern("2$")),
        make_config("https://issuer3",
                    "prefix3",
                    "audience3",
                    SetMatchPattern(".*")),  // matches all
    };

    auto registry = create_registry(configs);

    {
        // Expect first idp if no principal name provided
        const auto idp = registry.getIdpForPrincipalName(boost::none);
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        // Expect first idp since principal name matches first idp
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("user1"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        // Expect second idp since principal name matches second idp
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("user2"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[1]);
    }
    {
        // Expect third idp since third idp's match pattern matches all
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("user3"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[2]);
    }
    {
        // Expect third idp since third idp's match pattern matches all
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("user4"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[2]);
    }
    {
        // Expect third idp since third idp's match pattern matches all
        const auto idp = registry.getIdpForPrincipalName(make_principal_name("some_user"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[2]);
    }
}

// Test for getting the JWKManager by issuer
TEST_F(OidcIdentityProvidersRegistryTest, getJWKManager_Success) {
    std::vector configs{
        make_config("https://issuer1", "prefix1", "audience1", SetSupportsHumanFlows(true)),
        make_config("https://issuer2", "prefix1", "audience2", SetSupportsHumanFlows(false)),
    };

    auto registry = create_registry(configs);

    // expect JWKManager for both issuers
    ASSERT_NE(registry.getJWKManager("https://issuer1"), nullptr);
    ASSERT_NE(registry.getJWKManager("https://issuer2"), nullptr);

    // expect no JWKManager for unknown issuer
    ASSERT_EQ(registry.getJWKManager("https://issuer3"), nullptr);
}

// Test for starting the JWKSPolling jobs with correct periods
TEST_F(OidcIdentityProvidersRegistryTest, JWKSPollSecs_JobsStarted) {
    std::vector configs{
        make_config("https://issuer1", "prefix", "audience1", SetJWKSPollSecs(1)),
        make_config("https://issuer1", "prefix", "audience2", SetJWKSPollSecs(1)),  // same issuer
        make_config("https://issuer2", "prefix", "audience3", SetJWKSPollSecs(2)),
    };

    auto registry = create_registry(configs);

    // expect 2 jobs created, one for each unique issuer
    ASSERT_EQ(_periodicRunnerMock.jobs.size(), 2);

    // expect both jobs have correct periods and are started
    ASSERT_EQ(_periodicRunnerMock.jobs[0]->getPeriod(), Milliseconds(Seconds(1)));
    ASSERT_TRUE(_periodicRunnerMock.jobs[0]->isStarted());

    ASSERT_EQ(_periodicRunnerMock.jobs[1]->getPeriod(), Milliseconds(Seconds(2)));
    ASSERT_TRUE(_periodicRunnerMock.jobs[1]->isStarted());
}

}  // namespace
}  // namespace mongo
