## Batch and call sponsor contract

> [!WARNING]
> This contract hasn't been audited and is still work in progress. Don't use in production.

This contract will be used for gas sponsorship. In order to allow sponsoring gas the user will have to sign an [EIP 7702](https://eips.ethereum.org/EIPS/eip-7702) authorization with this contract as a template. The authorization can then be broacasted by a third party and sponsored the gas for this user.

## Run tests

There is a simple test that proceed to do the delegation to Bob and have Bob executing a ERC20 transfer. And another test that verify that we can't resend an already submitted call.

```bash
$ forge test -vvv
```

## Security considerations

* Authorizations are permanent. Once the transaction executed the EOA keep its bytecodes until it is being reversed by signing an authorization to the zero address.

* Any storage set at the EOA address is persitent between authorization. The storage should be cleared.

* The contract can be called by anyone. It should be consider to limit the access to only the some sponsors. The previous point should be consider if we start to store address that can run `execute` calls.


