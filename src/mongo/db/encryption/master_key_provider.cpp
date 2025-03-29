/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2022-present Percona and/or its affiliates. All rights reserved.

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


#include "mongo/db/encryption/master_key_provider.h"

#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/encryption/error_builder.h"
#include "mongo/db/encryption/key.h"
#include "mongo/db/encryption/key_entry.h"
#include "mongo/db/encryption/key_id.h"
#include "mongo/db/encryption/key_operations.h"
#include "mongo/logv2/log.h"
#include "mongo/logv2/log_options.h"
#include "mongo/stdx/thread.h"
#include "mongo/util/exit.h"
#include "mongo/util/exit_code.h"
#include "mongo/util/periodic_runner.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kDefault


namespace mongo::encryption {
MasterKeyProvider::~MasterKeyProvider() = default;

MasterKeyProvider::MasterKeyProvider(std::unique_ptr<const KeyOperationFactory>&& factory,
                                     WtKeyIds& wtKeyIds,
                                     logv2::LogComponent logComponent)
    : _factory(std::move(factory)), _wtKeyIds(wtKeyIds), _logComponent(logComponent) {}

std::unique_ptr<MasterKeyProvider> MasterKeyProvider::create(const EncryptionGlobalParams& params,
                                                             logv2::LogComponent logComponent) {
    return std::make_unique<MasterKeyProvider>(
        KeyOperationFactory::create(params), WtKeyIds::instance(), logComponent);
}

KeyEntry MasterKeyProvider::_readMasterKey(const ReadKey& read, bool updateKeyIds) const {
    std::variant<KeyEntry, NotFound, BadKeyState> readResult = read();
    if (readResult.index() > 0) {
        const char* reason = readResult.index() == 1
            ? "Cannot start. Master encryption key is absent on the "
              "key management facility. Check configuration options."
            : "Master encryption key is not in the active state on the key management facility.";
        KeyErrorBuilder b(KeyOperationType::kRead, reason);
        b.append("keyManagementFacilityType", read.facilityType());
        b.append("keyIdentifier", read.keyId());
        if (readResult.index() == 2) {
            b.append("keyState", toString(std::get<2>(readResult)));
        }
        throw b.error();
    }

    KeyEntry keyEntry = std::move(std::get<0>(readResult));
    if (updateKeyIds) {
        _wtKeyIds.decryption = keyEntry.keyId->clone();
        if (!_wtKeyIds.configured &&
            _wtKeyIds.decryption->needsSerializationToStorageEngineEncryptionOptions()) {
            _wtKeyIds.futureConfigured = _wtKeyIds.decryption->clone();
        }
    }
    LOGV2_OPTIONS(29115,
                  logv2::LogOptions(_logComponent),
                  "Master encryption key has been read from the key management facility.",
                  "keyManagementFacilityType"_attr = read.facilityType(),
                  "keyIdentifier"_attr = *keyEntry.keyId);
    return keyEntry;
}

std::unique_ptr<KeyId> MasterKeyProvider::_saveMasterKey(const SaveKey& save,
                                                         const Key& key) const {
    std::unique_ptr<KeyId> keyId = save(key);
    invariant(keyId);
    if (keyId->needsSerializationToStorageEngineEncryptionOptions()) {
        _wtKeyIds.futureConfigured = keyId->clone();
    }
    LOGV2_OPTIONS(29116,
                  logv2::LogOptions(_logComponent),
                  "Master encryption key has been created on the key management facility",
                  "keyManagementFacilityType"_attr = keyId->facilityType(),
                  "keyIdentifier"_attr = *keyId);
    return keyId;
}

KeyEntry MasterKeyProvider::readMasterKey() const {
    return _readMasterKey(*_factory->createRead(_wtKeyIds.configured.get()));
}

KeyEntry MasterKeyProvider::obtainMasterKey(bool saveKey) const {
    if (auto read = _factory->createProvidedRead(); read) {
        auto keyEntry = _readMasterKey(*read, false);
        if (keyEntry.keyId->needsSerializationToStorageEngineEncryptionOptions()) {
            _wtKeyIds.futureConfigured = keyEntry.keyId->clone();
        }
        return keyEntry;
    }

    Key key;
    std::unique_ptr<KeyId> keyId;
    if (saveKey) {
        keyId = _saveMasterKey(*_factory->createSave(_wtKeyIds.configured.get()), key);
    }
    return {key, std::move(keyId)};
}

void MasterKeyProvider::saveMasterKey(const Key& key) const {
    _saveMasterKey(*_factory->createSave(_wtKeyIds.configured.get()), key);
}

namespace {
class KeyStateMonitor {
public:
    KeyStateMonitor(std::shared_ptr<GetKeyState> getState, logv2::LogComponent logComponent)
        : _getState((invariant(getState), getState)), _logComponent(logComponent) {}

    void operator()([[maybe_unused]] Client* client) const;

private:
    std::shared_ptr<GetKeyState> _getState;
    logv2::LogComponent _logComponent;
};

void KeyStateMonitor::operator()([[maybe_unused]] Client* client) const try {
    std::optional<KeyState> state = (*_getState)();
    if (state && *state == KeyState::kActive) {
        return;
    }
    if (!state) {
        LOGV2_ERROR_OPTIONS(29124,
                            logv2::LogOptions(_logComponent),
                            "Master encryption key is absent on the key management facility.",
                            "keyManagementFacilityType"_attr = _getState->facilityType(),
                            "keyIdentifier"_attr = _getState->keyId());
    } else {  // state is not `KeyState::kActive`
        LOGV2_ERROR_OPTIONS(29122,
                            logv2::LogOptions(_logComponent),
                            "Master encryption key is not in the active "
                            "state on the key management facility.",
                            "keyManagementFacilityType"_attr = _getState->facilityType(),
                            "keyIdentifier"_attr = _getState->keyId(),
                            "keyState"_attr = toString(*state));
    }
    // Please note that launching a new detached thread for calling `shutdown`
    // is essential here. The `KeyStateMonitor::operator()` is going to be
    // called from within a particular thread associated with a `PeriodicJob`.
    // The `shutdown` function eventually leads to the call to
    // `PeriodicRunnerImpl::PeriodicJobImpl::stop` which joins the thread.
    // If it were called directly, `shutdown` would result in a thread
    // joining itself. The idea of launching a detached thread was adopted
    // from `src/mongo/db/commands/shutdown.cpp`.
    stdx::thread([] { shutdown(ExitCode::perconaDataAtRestEncryptionError); }).detach();
} catch (const encryption::Error& e) {
    // If the KMIP server is unavailable when key state verification job
    // tries to reach it, then the `encryption::Error` exception is thrown.
    // In that case, we just need to log the error and wait for another attempt,
    // which will be done in `verify->period()` seconds. Please see the
    // `registerKeyStateVerificationJob` member function below.
    LOGV2_ERROR_OPTIONS(
        29123, logv2::LogOptions(_logComponent), "Data-at-Rest Encryption Error", "error"_attr = e);
}
}  // namespace

PeriodicJobAnchor MasterKeyProvider::registerKeyStateVerificationJob(PeriodicRunner& pr,
                                                                     const KeyId& keyId) const {
    auto getState = std::shared_ptr<GetKeyState>(_factory->createGetState(keyId));
    if (!getState) {
        return PeriodicJobAnchor();
    }
    return pr.makeJob(PeriodicRunner::PeriodicJob("KeyStateMonitor",
                                                  KeyStateMonitor(getState, _logComponent),
                                                  getState->period(),
                                                  /* isKillableByStepdown = */ false));
}
}  // namespace mongo::encryption
