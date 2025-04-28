import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var idp_config = {
    token: [
        {
            payload: {
                aud: "audience",
                sub: "user",
                claim: [
                    "group1",
                    "group2",
                ],
            }
        },
        {
            payload: {
                aud: "audience",
                sub: "user",
                claim: [],
            }
        },
        {
            payload: {
                aud: "audience",
                sub: "user",
                claim: ["group3"],
            }
        },
        {
            payload: {
                aud: "audience",
                sub: "user",
                claim: "group4",
            }
        }
    ]
};

var oidcProvider = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    authorizationClaim: "claim"
};

var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
test.setup();

test.create_role("test/group1", [{ role: "readWrite", db: "test_db1" }]);
test.create_role("test/group2", [{ role: "read", db: "test_db2" }]);

var conn = test.create_conn();

assert(test.auth(conn, "user"), "Failed to authenticate");
test.assert_authenticated(conn, "test/user", [
    "test/group1",
    "test/group2",
    { role: "readWrite", db: "test_db1" },
    { role: "read", db: "test_db2" },
]);
test.logout(conn);

test.auth(conn, "user");
test.assert_authenticated(conn, "test/user", []);
test.logout(conn);

test.auth(conn, "user");
test.assert_authenticated(conn, "test/user", ["test/group3"]);
test.logout(conn);

test.auth(conn, "user");
test.assert_authenticated(conn, "test/user", ["test/group4"]);
test.logout(conn);

test.teardown();
