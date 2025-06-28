/**
 * Test the use of "explain" with the "$search" aggregation stage. This tests all verbosities
 * and tests when mongot returns explain only as well as explain with cursor response.
 */
import {FeatureFlagUtil} from "jstests/libs/feature_flag_util.js";
import {checkSbeRestrictedOrFullyEnabled} from "jstests/libs/sbe_util.js";
import {getUUIDFromListCollections} from "jstests/libs/uuid_util.js";
import {
    mongotCommandForQuery,
    MongotMock,
} from "jstests/with_mongot/mongotmock/lib/mongotmock.js";
import {
    getDefaultLastExplainContents,
    getSearchStagesAndVerifyExplainOutput,
    setUpMongotReturnExplain,
    setUpMongotReturnExplainAndCursor,
    setUpMongotReturnExplainAndCursorGetMore,
} from "jstests/with_mongot/mongotmock/lib/utils.js";

// Set up mongotmock and point the mongod to it.
const mongotmock = new MongotMock();
mongotmock.start();
const mongotConn = mongotmock.getConnection();

const conn = MongoRunner.runMongod({setParameter: {mongotHost: mongotConn.host}});
const dbName = jsTestName();
const db = conn.getDB(dbName);
const coll = db.search;
coll.drop();
const collName = coll.getName();

const explainObject = getDefaultLastExplainContents();

if (checkSbeRestrictedOrFullyEnabled(db) &&
    FeatureFlagUtil.isPresentAndEnabled(db.getMongo(), 'SearchInSbe')) {
    jsTestLog("Skipping the test because it only applies to $search in classic engine.");
    MongoRunner.stopMongod(conn);
    mongotmock.stop();
    quit();
}

assert.commandWorked(coll.insert({_id: 1, name: "Chekhov"}));
assert.commandWorked(coll.insert({_id: 2, name: "Dostoevsky"}));
assert.commandWorked(coll.insert({_id: 5, name: "Pushkin"}));
assert.commandWorked(coll.insert({_id: 6, name: "Tolstoy"}));
assert.commandWorked(coll.insert({_id: 8, name: "Zamatyin"}));

const collUUID = getUUIDFromListCollections(db, coll.getName());

const searchQuery = {
    query: "Chekhov",
    path: "name"
};

function runExplainTest(verbosity) {
    const searchCmd = mongotCommandForQuery({
        query: searchQuery,
        collName: collName,
        db: dbName,
        collectionUUID: collUUID,
        explainVerbosity: {verbosity}
    });
    const pipeline = [{$search: searchQuery}];
    const stageType = "$_internalSearchMongotRemote";

    {  // TODO SERVER-91594: setUpMongotReturnExplain() should only be run for 'queryPlanner'
       // verbosity when
        // mongot always returns a cursor for execution stats.
        setUpMongotReturnExplain({
            searchCmd,
            mongotMock: mongotmock,
        });
        const result = coll.explain(verbosity).aggregate(pipeline);
        getSearchStagesAndVerifyExplainOutput(
            {result, stageType, verbosity, nReturned: NumberLong(0), explainObject});
    }
    if (verbosity != "queryPlanner") {
        {
            setUpMongotReturnExplainAndCursor({
                mongotMock: mongotmock,
                coll,
                searchCmd,
                nextBatch: [
                    {_id: 2, $searchScore: 0.654},
                    {_id: 1, $searchScore: 0.321},
                    {_id: 3, $searchScore: 0.123}
                ],
            });
            const result = coll.explain(verbosity).aggregate(pipeline);
            getSearchStagesAndVerifyExplainOutput({
                result,
                stageType,
                verbosity,
                nReturned: NumberLong(3),
                nReturnedIdLookup: NumberLong(2),
                explainObject
            });
        }
        {
            setUpMongotReturnExplainAndCursorGetMore({
                mongotMock: mongotmock,
                coll,
                searchCmd,
                batchList: [
                    [{_id: 0, $searchScore: 1.234}, {_id: 5, $searchScore: 1.21}],
                    [{_id: 2, $searchScore: 1.1}, {_id: 6, $searchScore: 0.8}],
                    [{_id: 8, $searchScore: 0.2}]
                ],
            });
            const result = coll.explain(verbosity).aggregate(pipeline, {cursor: {batchSize: 2}});
            getSearchStagesAndVerifyExplainOutput({
                result,
                stageType,
                verbosity,
                nReturned: NumberLong(5),
                nReturnedIdLookup: NumberLong(4),
                explainObject
            });
        }
    }
}

runExplainTest("queryPlanner");
runExplainTest("executionStats");
runExplainTest("allPlansExecution");

MongoRunner.stopMongod(conn);
mongotmock.stop();
