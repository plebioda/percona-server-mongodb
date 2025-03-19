(function() {
    'use strict';

    // prepare for the auth mode
    load('jstests/ldapauthz/_setup.js');

    // test command line parameters related to LDAP authorization
    var conn = MongoRunner.runMongod({
        auth: '',
        ldapServers: TestData.ldapServers,
        ldapTransportSecurity: 'none',
        ldapBindMethod: 'simple',
        ldapQueryUser: TestData.ldapQueryUser,
        ldapQueryPassword: TestData.ldapQueryPassword,
        ldapAuthzQueryTemplate: TestData.ldapAuthzQueryTemplate,
        setParameter: {authenticationMechanisms: 'PLAIN,SCRAM-SHA-256,SCRAM-SHA-1'}
    });

    assert(conn, "Cannot start mongod instance");

    // load check roles routine
    load('jstests/ldapauthz/_check.js');

    var db = conn.getDB('$external');

    const username = 'cn=' + "exttestro" + ',dc=percona,dc=com';
    const userpwd = 'exttestro9a5S';

    print('authenticating ' + username);

    assert(db.auth({
        user: username,
        pwd: userpwd,
        mechanism: 'PLAIN'
    }));

    // ensure user have got correct set of privileges
    print("\n\n\n\n\n############KEITH TEST#################\n\n\n\n\n")
    print(db.adminCommand({ getParameter: 1, "queryFramework.queryTemplate": 1 }))
    print("\n\n\n\n\n############KEITH TEST#################\n\n\n\n\n")

    var authenticatedUserRoles = JSON.stringify(db.runCommand({connectionStatus: 1}).authInfo.authenticatedUserRoles[0])
    assert(authenticatedUserRoles == '{"role":"cn=testreaders,dc=percona,dc=com","db":"admin"}')

    db.logout();

    MongoRunner.stopMongod(conn);
})();

