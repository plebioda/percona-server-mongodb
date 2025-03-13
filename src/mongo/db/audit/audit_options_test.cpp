/**
 *    Copyright (C) 2018-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */


#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/path.hpp"

#include "mongo/db/audit/audit_options.h"
#include "mongo/db/ldap_options.h"
#include "mongo/db/server_options.h"
#include "mongo/db/server_options_base.h"

#include "mongo/util/options_parser/environment.h"
#include "mongo/util/options_parser/value.h"

#include "mongo/unittest/assert.h"
#include "mongo/unittest/framework.h"
#include <utility>


namespace mongo {
namespace {
namespace moe = mongo::optionenvironment;
namespace fs = boost::filesystem;

#define ASSERT_BOOST_SUCCESS(ec) ASSERT_FALSE(ec) << ec.message()

// Set of util functions which asserts instead of throwing exceptions

// Creates an unique directory in system specific temporary directory
fs::path createTmpDir() {
    boost::system::error_code ec;

    const auto tmpDir =
        fs::temp_directory_path() / fs::unique_path("audit-test-%%%%-%%%%-%%%%-%%%%");
    fs::create_directories(tmpDir, ec);
    ASSERT_BOOST_SUCCESS(ec);

    return tmpDir;
}

// Changes current working directory
void changeDir(const fs::path& dir) {
    boost::system::error_code ec;

    fs::current_path(dir, ec);
    ASSERT_BOOST_SUCCESS(ec);
}

// Removes all from given path
void removeAll(const fs::path& path) {
    boost::system::error_code ec;

    fs::remove_all(path, ec);
    ASSERT_BOOST_SUCCESS(ec);
}

// Returns current working directory
fs::path getCwd() {
    boost::system::error_code ec;

    const auto cwd = fs::current_path(ec);
    ASSERT_BOOST_SUCCESS(ec);

    return cwd;
}

template <typename T>
void set(moe::Environment& env, const moe::Key& key, T&& value) {
    ASSERT_OK(env.set(key, moe::Value(std::forward<T>(value))));
}

class ValidateAuditOptionsTestFixture : public mongo::unittest::Test {
protected:
    static constexpr auto DefaultPathJson = "auditLog.json";
    static constexpr auto DefaultPathBson = "auditLog.bson";

    void setUp() override {
        // Reset audit options and set up default server parameters
        auditOptions = AuditOptions();

        _cwd = getCwd();
        _tmpDir = createTmpDir();
        changeDir(_tmpDir);

        // make sure cwd is correct
        serverGlobalParams.cwd = getCwd().string();
    }

    void tearDown() override {
        // Restore the original working directory and clean up the temporary directory
        changeDir(_cwd);
        removeAll(_tmpDir);

        _cwd = fs::path();
        _tmpDir = fs::path();
    }

private:
    fs::path _cwd;
    fs::path _tmpDir;
};

// Test default behavior when no audit log options are set
TEST_F(ValidateAuditOptionsTestFixture, Default) {
    moe::Environment env;

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, getCwd() / DefaultPathJson);
    ASSERT_TRUE(fs::exists(DefaultPathJson));
}

// Test BSON format with default path
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_FormatBSON_DefaultPath) {
    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.format", "BSON");

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, getCwd() / DefaultPathBson);
    ASSERT_TRUE(fs::exists(DefaultPathBson));
}

// Test JSON format with default path
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_FormatJSON_DefaultPath) {
    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.format", "JSON");

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, getCwd() / DefaultPathJson);
    ASSERT_TRUE(fs::exists(DefaultPathJson));
}

// Test BSON format with default path derived from log path
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_FormatBSON_DefaultPathFromLog) {
    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.format", "BSON");

    const auto tmpDir = createTmpDir();
    serverGlobalParams.logpath = (tmpDir / "log.log").string();

    ScopeGuard sg = [&] {
        removeAll(tmpDir);
    };

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, tmpDir / DefaultPathBson);
    ASSERT_TRUE(fs::exists(tmpDir / DefaultPathBson));
}

// Test JSON format with default path derived from log path
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_FormatJSON_DefaultPathFromLog) {
    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.format", "JSON");

    const auto tmpDir = createTmpDir();
    serverGlobalParams.logpath = (tmpDir / "log.log").string();
    ScopeGuard sg = [tmpDir] {
        removeAll(tmpDir);
    };

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, tmpDir / DefaultPathJson);
    ASSERT_TRUE(fs::exists(tmpDir / DefaultPathJson));
}

// Test custom path for audit log file
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_CustomPath) {
    const auto path = "auditFileName.json";

    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.path", path);

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, getCwd() / path);
    ASSERT_TRUE(fs::exists(path));
}

// Test custom path when the directory does not exist
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_CustomPath_DirectoryNotExists) {
    const auto path = "bad_dir/auditFileName.json";

    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.path", path);

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_EQ(validateAuditOptions(), ErrorCodes::BadValue);
}

// Test custom path with simulated fork (changing working directory)
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_CustomPath_Fork) {
    const auto path = "auditFileName.json";

    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.path", path);

    // Simulate fork by changing current working directory
    const auto tmpDir = createTmpDir();
    const auto cwd = getCwd();
    changeDir(tmpDir);

    ScopeGuard sg = [cwd, tmpDir] {
        changeDir(cwd);
        removeAll(tmpDir);
    };

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, cwd / path);
    ASSERT_TRUE(fs::exists(cwd / path));
}

}  // namespace
}  // namespace mongo
