## Project Invariants

The PSMDB is a fork of MongoDB, and it is essential to maintain compatibility with MongoDB's features and APIs while integrating Percona's enhancements.

When resolving merge conflicts, adhere to the following guidelines:

1. Don't remove or alter any Percona-specific features, enhancements, or bug fixes.
2. Prioritize Percona's changes over MongoDB's when conflicts arise, however, make sure only relevant Percona's changes are kept. Any surrounging code that is not related to Percona's changes can be changed to match MongoDB's version.
3. Do not restrict the conflict resolution to only the lines marked by the conflict markers. Consider the surrounding code context to ensure a coherent and functional final version. Do not resolve conflict only by choosing apropriate block. Instead, try to merge the changes from both sides when possible.
4. Do not make any unrelated changes to the code.
5. ALWAYS make sure the conflict markers are COMPLETELY removed (<<<<<<<, =======, >>>>>>>, and |||||||) from the final code.
