import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url1 = OIDCFixture.allocate_issuer_url();
const issuer_url2 = OIDCFixture.allocate_issuer_url();
const issuer_url3 = OIDCFixture.allocate_issuer_url();

const oidcProviders = [
    {
        issuer: issuer_url1,
        clientId: "clientId",
        audience: "audience",
        matchPattern: "1$",
        authNamePrefix: "test",
        useAuthorizationClaim: false,
        JWKSPollSecs: 0,
    },
    {
        issuer: issuer_url2,
        clientId: "clientId",
        audience: "audience",
        matchPattern: "2$",
        authNamePrefix: "test",
        useAuthorizationClaim: false,
        JWKSPollSecs: 0,
    },
    {
        issuer: issuer_url3,
        clientId: "clientId",
        audience: "audience",
        matchPattern: "3$",
        authNamePrefix: "test",
        useAuthorizationClaim: false,
        JWKSPollSecs: 0,
    },
];

const idps = [
    {
        url: issuer_url1,
        config: {
            number_of_jwks: 3,
        }
    },
    {
        url: issuer_url2,
        config: {
            number_of_jwks: 2,
        }
    },
    {
        url: issuer_url3,
        config: {
            number_of_jwks: 1,
        }
    },
];

var test = new OIDCFixture({ oidcProviders: oidcProviders, idps: [] });
test.setup();

sleep(1000);

const verifyKeys = (keys, issuer_url, expectedNumberOfKeys) => {
    assert(keys.keySets, "oidcListKeys should have keySets");
    assert(keys.keySets[issuer_url], "oidcListKeys should have keySets for issuer_url");
    assert(keys.keySets[issuer_url].keys, "key set for issuer_url should have keys");
    assert.eq(keys.keySets[issuer_url].keys.length, expectedNumberOfKeys, `key set for ${issuer_url} should have ${expectedNumberOfKeys} keys`);
}

const verifyAllKeys = (count1, count2, count3) => {
    const keys = assert.commandWorked(test.admin.runCommand({ oidcListKeys: 1 }), "oidcListKeys should work");

    verifyKeys(keys, issuer_url1, count1);
    verifyKeys(keys, issuer_url2, count2);
    verifyKeys(keys, issuer_url3, count3);
}

verifyAllKeys(0, 0, 0);

for (const idp of idps) {
    test.create_idp(idp.url, idp.config).start();
}

sleep(1000);

verifyAllKeys(0, 0, 0);

for (const idp of idps) {
    test.get_idp(idp.url).assert_no_http_request("GET", "/keys");
}

assert.commandWorked(test.admin.runCommand({ oidcRefreshKeys: 1 }), "oidcRefreshKeys should work");

for (const idp of idps) {
    test.get_idp(idp.url).assert_http_request("GET", "/keys");
}

verifyAllKeys(3, 2, 1);

test.teardown();
