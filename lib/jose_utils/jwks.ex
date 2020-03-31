defmodule JOSEUtils.JWKS do
  @moduledoc """
  Util function to work with JWK sets
  """

  @type t :: [JOSEUtils.JWK.t()]

  @doc """
  Returns the keys suitable for signature from a JWK set

  Note that it does **not** return the keys suitable for signature verification
  """
  @spec signature_keys(
    t(),
    alg_or_algs :: JOSEUtils.JWA.sig_alg() | [JOSEUtils.JWA.sig_alg()] | nil
  ) :: t()
  def signature_keys(jwks, alg_or_algs \\ nil)

  def signature_keys(jwks, nil) do
    jwks
    |> Enum.filter(fn jwk -> jwk["use"] == nil or jwk["use"] == "sig" end)
    |> Enum.filter(fn jwk -> jwk["key_ops"] == nil or "sign" in jwk["key_ops"] end)
  end

  def signature_keys(jwks, algs) when is_list(algs) do
    jwks
    |> Enum.filter(fn jwk -> jwk["alg"] == nil or jwk["alg"] in algs end)
    |> signature_keys()
  end

  def signature_keys(jwks, alg) when is_binary(alg) do
    signature_keys(jwks, [alg])
  end

  @doc """
  Returns the keys suitable for signature **verification** from a JWK set
  """
  @spec verification_keys(
    t(),
    alg_or_algs :: JOSEUtils.JWA.sig_alg() | [JOSEUtils.JWA.sig_alg()] | nil
  ) :: t()
  def verification_keys(jwks, alg_or_algs \\ nil)

  def verification_keys(jwks, nil) do
    jwks
    |> Enum.filter(fn jwk -> jwk["use"] == nil or jwk["use"] == "sig" end)
    |> Enum.filter(fn jwk -> jwk["key_ops"] == nil or "verify" in jwk["key_ops"] end)
  end

  def verification_keys(jwks, algs) when is_list(algs) do
    jwks
    |> Enum.filter(fn jwk -> jwk["alg"] == nil or jwk["alg"] in algs end)
    |> verification_keys()
  end

  def verification_keys(jwks, alg) when is_binary(alg) do
    verification_keys(jwks, [alg])
  end

  @doc """
  Returns the keys suitable for encryption from a JWK set
  """
  @spec encryption_keys(
    t(),
    alg_or_algs :: JOSEUtils.JWA.sig_alg() | [JOSEUtils.JWA.sig_alg()] | nil
  ) :: t()
  def encryption_keys(jwks, alg_or_algs \\ nil)

  def encryption_keys(jwks, nil) do
    jwks
    |> Enum.filter(fn jwk -> jwk["use"] == nil or jwk["use"] == "enc" end)
    |> Enum.filter(fn jwk ->
      jwk["key_ops"] == nil or "encrypt" in jwk["key_ops"] or "deriveKey" in jwk["key_ops"]
    end)
  end

  def encryption_keys(jwks, algs) when is_list(algs) do
    jwks
    |> Enum.filter(fn jwk -> jwk["alg"] == nil or jwk["alg"] in algs end)
    |> encryption_keys()
  end

  def encryption_keys(jwks, alg) when is_binary(alg) do
    encryption_keys(jwks, [alg])
  end

  @doc """
  Returns the keys suitable for decryption from a JWK set
  """
  @spec decryption_keys(
    t(),
    alg_or_algs :: JOSEUtils.JWA.sig_alg() | [JOSEUtils.JWA.sig_alg()] | nil
  ) :: t()
  def decryption_keys(jwks, alg_or_algs \\ nil, enc_or_encs \\ nil)

  def decryption_keys(jwks, nil, nil) do
    jwks
    |> Enum.filter(fn jwk -> jwk["use"] == nil or jwk["use"] == "enc" end)
    |> Enum.filter(fn jwk -> jwk["key_ops"] == nil or "decrypt" in jwk["key_ops"] end)
  end

  def decryption_keys(jwks, algs, nil) when is_list(algs) do
    jwks
    |> Enum.filter(fn jwk -> jwk["alg"] == nil or jwk["alg"] in algs end)
    |> decryption_keys()
  end

  def decryption_keys(jwks, algs, enc) when is_list(algs) do
    jwks
    |> Enum.filter(fn jwk -> jwk["enc"] == nil or jwk["enc"] in enc end)
    |> decryption_keys(algs)
  end

  def decryption_keys(jwks, alg, enc_or_encs) when is_binary(alg) do
    decryption_keys(jwks, [alg], enc_or_encs)
  end

  def decryption_keys(jwks, alg_or_algs, enc) when is_binary(enc) do
    decryption_keys(jwks, alg_or_algs, enc)
  end
end
