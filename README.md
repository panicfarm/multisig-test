These are real blockchain transactions examples of computing sighash for P2WKH, P2MS, P2SH multisig and P2WSH multisigs.

It is currently **lacking P2TR** examples.

For M of N multisigs, the tests verify that M from the N keys from the ScriptPubKey do correspond to the M input's signatures, given the sighash computation.
The sighash computation is inspired by [Andrew Poelstra's comment](https://bitcoin.stackexchange.com/a/117478/137810).

To run all the tests with verified PubKeys printouts use:

`cargo test -- --nocapture`
