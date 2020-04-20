# JOSEUtils

Convenience functions to work with JOSE (JSON Object Signing and Encryption)

## Installation

```elixir
def deps do
  [
    {:jose_utils, "~> 0.1.0"}
  ]
end
```

## Functions

### JWS

```elixir
@spec verify(
        jws :: serialized(),
        jwk_or_jwks :: JOSEUtils.JWK.t() | [JOSEUtils.JWK.t()],
        allowed_algs :: [JOSEUtils.JWA.sig_alg()]
      ) :: {:ok, {verified_content :: binary(), JOSEUtils.JWK.t()}} | :error
```

### JWE

```elixir
@spec decrypt(
        jwe :: serialized(),
        jwk_or_jwks :: JOSEUtils.JWK.t() | [JOSEUtils.JWK.t()],
        allowed_algs :: [JOSEUtils.JWA.enc_alg()],
        allowed_encs :: [JOSEUtils.JWA.enc_enc()]
      ) :: {:ok, {decrypted_message :: binary(), JOSEUtils.JWK.t()}} | :error
```

### JWK

```elixir
@spec sig_alg_digest(t()) :: atom()

@spec verify(t()) :: result()
```

### JWKS

```elixir
@spec signature_keys(
        t(),
        alg_or_algs :: JOSEUtils.JWA.sig_alg() | [JOSEUtils.JWA.sig_alg()] | nil
      ) :: t()

@spec verification_keys(
        t(),
        alg_or_algs :: JOSEUtils.JWA.sig_alg() | [JOSEUtils.JWA.sig_alg()] | nil
      ) :: t()

@spec encryption_keys(
        t(),
        alg_or_algs :: JOSEUtils.JWA.enc_alg() | [JOSEUtils.JWA.enc_alg()] | nil,
        enc_or_encs :: JOSEUtils.JWA.enc_enc() | [JOSEUtils.JWA.enc_enc()] | nil
      ) :: t()

@spec decryption_keys(
        t(),
        alg_or_algs :: JOSEUtils.JWA.enc_alg() | [JOSEUtils.JWA.enc_alg()] | nil,
        enc_or_encs :: JOSEUtils.JWA.enc_enc() | [JOSEUtils.JWA.enc_enc()] | nil
      ) :: t()
```
