defmodule JOSEUtils.JWKS do
  @moduledoc """
  Convenience function to work with JWK sets
  """

  alias JOSEUtils.{JWA, JWK}

  @type t :: [JWK.t()]

  @doc """
  Filters the JWKS using a key selector `t:JWK.key_selector/0`
  """
  @spec filter(t(), JWK.key_selector()) :: t()
  def filter(jwks, key_selector),
    do: Enum.filter(jwks, fn jwk -> JWK.match_key_selector?(jwk, key_selector) end)

  @doc """
  Returns the keys suitable for signature from a JWK set

  Note that it does **not** return the keys suitable only for signature verification.

  MAC keys are considered signature keys, and are returned as well.
  """
  @spec signature_keys(
          t(),
          alg_or_algs :: JWA.sig_alg() | [JWA.sig_alg()] | nil
        ) :: t()
  def signature_keys(jwks, alg_or_algs \\ nil)
  def signature_keys(jwks, nil), do: filter(jwks, use: "sig", key_ops: "sign")
  def signature_keys(jwks, alg_or_algs),
    do: filter(jwks, use: "sig", key_ops: "sign", alg: alg_or_algs)

  @doc """
  Returns the keys suitable for signature **verification** from a JWK set

  MAC keys are considered verification keys, and are returned as well.
  """
  @spec verification_keys(
          t(),
          alg_or_algs :: JWA.sig_alg() | [JWA.sig_alg()] | nil
        ) :: t()
  def verification_keys(jwks, alg_or_algs \\ nil)
  def verification_keys(jwks, nil), do: filter(jwks, use: "sig", key_ops: "sign")
  def verification_keys(jwks, alg_or_algs),
    do: filter(jwks, use: "sig", key_ops: "verify", alg: alg_or_algs)

  @doc """
  Returns the keys suitable for encryption from a JWK set
  """
  @spec encryption_keys(
          t(),
          alg_or_algs :: JWA.enc_alg() | [JWA.enc_alg()] | nil,
          enc_or_encs :: JWA.enc_enc() | [JWA.enc_enc()] | nil
        ) :: t()
  def encryption_keys(jwks, alg_or_algs \\ nil, enc_or_encs \\ nil)
  def encryption_keys(jwks, nil, nil),
    do: filter(jwks, use: "enc", key_ops: ["encrypt", "deriveKey"])
  def encryption_keys(jwks, algs, nil),
    do: filter(jwks, use: "enc", key_ops: ["encrypt", "deriveKey"], alg: algs)
  def encryption_keys(jwks, algs, encs),
    do: filter(jwks, use: "enc", key_ops: ["encrypt", "deriveKey"], alg: algs, enc: encs)

  @doc """
  Returns the keys suitable for decryption from a JWK set
  """
  @spec decryption_keys(
          t(),
          alg_or_algs :: JWA.enc_alg() | [JWA.enc_alg()] | nil,
          enc_or_encs :: JWA.enc_enc() | [JWA.enc_enc()] | nil
        ) :: t()
  def decryption_keys(jwks, alg_or_algs \\ nil, enc_or_encs \\ nil)
  def decryption_keys(jwks, nil, nil),
    do: filter(jwks, use: "enc", key_ops: "decrypt")
  def decryption_keys(jwks, algs, nil),
    do: filter(jwks, use: "enc", key_ops: "decrypt", alg: algs)
  def decryption_keys(jwks, algs, encs),
    do: filter(jwks, use: "enc", key_ops: "decrypt", alg: algs, enc: encs)
end
