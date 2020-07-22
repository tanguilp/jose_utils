defmodule JOSEUtils.JWK do
  @moduledoc """
  Convenience functions to work with JWKs
  """

  alias JOSEUtils.JWA

  @typedoc """
  A JSON Web Key in its map form

  For instance:

      %{
        "crv" => "P-256",
        "kty" => "EC",
        "x" => "6pwDpICQ8JBWdvuLuXeWILAxSEUNB_BBAswikgYKKmY",
        "y" => "fEHj1ehsIJ7PP-qon-oONl_J2yZLWpUncNRedZT7xqs"
      }
  """
  @type t :: %{required(String.t()) => any()}

  # X509.Certificate.t()
  @type certificate :: any()

  @type key_selector :: [key_selector_opt()]

  @type key_selector_opt ::
  {:alg, JWA.sig_alg() | JWA.enc_alg | [JWA.sig_alg()] | [JWA.enc_alg()]}
  | {:crv, JWA.crv() | [JWA.crv()]}
  | {:enc, JWA.enc_enc() | [JWA.enc_enc()]}
  | {:key_ops, key_op() | [key_op()]}
  | {:kid, kid()}
  | {:kty, kty() | [kty()]}
  | {:use, use()}

  @type kty :: String.t()
  @type use :: String.t()
  @type key_op :: String.t()
  @type kid :: String.t()

  @type result :: :ok | {:error, atom()}

  @doc """
  Returns the key type for an algorithm or `nil` for the `"none"` and `"dir"` algorithms

  ## Example

      iex> JOSEUtils.JWK.key_type_for_alg("RS512")
      "RSA"

      iex> JOSEUtils.JWK.key_type_for_alg("ECDH-ES+A128KW")
      "EC"

      iex> JOSEUtils.JWK.key_type_for_alg("dir")
      nil
  """
  @spec key_type_for_alg(JWA.sig_alg() | JWA.enc_alg()) :: kty()
  def key_type_for_alg("HS256"), do: "oct"
  def key_type_for_alg("HS384"), do: "oct"
  def key_type_for_alg("HS512"), do: "oct"
  def key_type_for_alg("RS256"), do: "RSA"
  def key_type_for_alg("RS384"), do: "RSA"
  def key_type_for_alg("RS512"), do: "RSA"
  def key_type_for_alg("ES256"), do: "EC"
  def key_type_for_alg("ES384"), do: "EC"
  def key_type_for_alg("ES512"), do: "EC"
  def key_type_for_alg("PS256"), do: "RSA"
  def key_type_for_alg("PS384"), do: "RSA"
  def key_type_for_alg("PS512"), do: "RSA"
  def key_type_for_alg("EdDSA"), do: "OKP"
  def key_type_for_alg("ES256K"), do: "EC"
  def key_type_for_alg("none"), do: nil
  def key_type_for_alg("RSA1_5"), do: "RSA"
  def key_type_for_alg("RSA-OAEP"), do: "RSA"
  def key_type_for_alg("RSA-OAEP-256"), do: "RSA"
  def key_type_for_alg("A128KW"), do: "oct"
  def key_type_for_alg("A192KW"), do: "oct"
  def key_type_for_alg("A256KW"), do: "oct"
  def key_type_for_alg("dir"), do: nil
  def key_type_for_alg("ECDH-ES"), do: "EC"
  def key_type_for_alg("ECDH-ES+A128KW"), do: "EC"
  def key_type_for_alg("ECDH-ES+A192KW"), do: "EC"
  def key_type_for_alg("ECDH-ES+A256KW"), do: "EC"
  def key_type_for_alg("A128GCMKW"), do: "oct"
  def key_type_for_alg("A192GCMKW"), do: "oct"
  def key_type_for_alg("A256GCMKW"), do: "oct"
  def key_type_for_alg("PBES2-HS256+A128KW"), do: "oct"
  def key_type_for_alg("PBES2-HS384+A192KW"), do: "oct"
  def key_type_for_alg("PBES2-HS512+A256KW"), do: "oct"

  @doc """
  Returns `true` if the key conforms to the key selector specification, `false` otherwise

  ## Examples

      iex> JOSE.JWK.generate_key({:ec, "P-256"}) |> Map.put(:fields, %{"kid" => "key_id"}) |> JOSE.JWK.to_map |> elem(1) |> JOSEUtils.JWK.match_key_selector?([])
      true

      iex> JOSE.JWK.generate_key({:ec, "P-256"}) |> Map.put(:fields, %{"kid" => "key_id"}) |> JOSE.JWK.to_map |> elem(1) |> JOSEUtils.JWK.match_key_selector?([kid: "abc"])
      false

      iex> JOSE.JWK.generate_key({:ec, "P-256"}) |> Map.put(:fields, %{"kid" => "key_id"}) |> JOSE.JWK.to_map |> elem(1) |> JOSEUtils.JWK.match_key_selector?([kty: "EC"])
      true

      iex> JOSE.JWK.generate_key({:ec, "P-256"}) |> Map.put(:fields, %{"kid" => "key_id"}) |> JOSE.JWK.to_map |> elem(1) |> JOSEUtils.JWK.match_key_selector?([kty: "RSA"])
      false

      iex> JOSE.JWK.generate_key({:ec, "P-256"}) |> Map.put(:fields, %{"kid" => "key_id"}) |> JOSE.JWK.to_map |> elem(1) |> JOSEUtils.JWK.match_key_selector?([use: "sig"])
      true

      iex> JOSE.JWK.generate_key({:ec, "P-256"}) |> Map.put(:fields, %{"kid" => "key_id"}) |> JOSE.JWK.to_map |> elem(1) |> JOSEUtils.JWK.match_key_selector?([use: "enc"])
      true

      iex> JOSE.JWK.generate_key({:ec, "P-256"}) |> Map.put(:fields, %{"kid" => "key_id"}) |> JOSE.JWK.to_map |> elem(1) |> JOSEUtils.JWK.match_key_selector?([key_ops: "a"])
      true

      iex> JOSE.JWK.generate_key({:ec, "P-256"}) |> Map.put(:fields, %{"kid" => "key_id"}) |> JOSE.JWK.to_map |> elem(1) |> JOSEUtils.JWK.match_key_selector?([key_ops: "sign"])
      true

      iex> JOSE.JWK.generate_key({:ec, "P-256"}) |> Map.put(:fields, %{"kid" => "key_id"}) |> JOSE.JWK.to_map |> elem(1) |> JOSEUtils.JWK.match_key_selector?([alg: ["ES256", "ES512"]])
      true

      iex> JOSE.JWK.generate_key({:ec, "P-256"}) |> Map.put(:fields, %{"alg" => "ES384"}) |> JOSE.JWK.to_map |> elem(1) |> JOSEUtils.JWK.match_key_selector?([alg: ["ES256", "ES512"]])
      false
  """
  @spec match_key_selector?(t(), key_selector()) :: boolean()
  def match_key_selector?(%{} = jwk, key_selector) do
    key_selector =
      key_selector
      |> Enum.into(%{})
      |> simple_value_to_list(:alg)
      |> simple_value_to_list(:crv)
      |> simple_value_to_list(:enc)
      |> simple_value_to_list(:key_ops)
      |> simple_value_to_list(:kty)

    do_match_key_selector?(jwk, key_selector)
  end

  defp simple_value_to_list(key_selector, field) do
    case key_selector[field] do
      <<_::binary>> = value ->
        Map.put(key_selector, field, [value])

      _ ->
        key_selector
    end
  end

  defp do_match_key_selector?(%{"kid" => kid}, %{kid: kid}) do
    true
  end

  defp do_match_key_selector?(_, %{kid: _}) do
    false
  end

  defp do_match_key_selector?(jwk, key_selector) do
    key_selector_use_valid?(jwk, key_selector) and
    key_selector_key_ops_valid?(jwk, key_selector) and
    key_selector_kty_valid?(jwk, key_selector) and
    key_selector_alg_valid?(jwk, key_selector) and
    key_selector_enc_valid?(jwk, key_selector) and
    key_selector_crv_valid?(jwk, key_selector)
  end

  defp key_selector_use_valid?(%{"use" => use}, %{use: use}), do: true
  defp key_selector_use_valid?(%{"use" => _}, %{use: _}), do: false
  defp key_selector_use_valid?(_, _), do: true

  defp key_selector_key_ops_valid?(%{"key_ops" => jwk_key_ops}, %{key_op: key_ops}),
    do: Enum.any?(key_ops, fn key_op -> key_op in jwk_key_ops end)
  defp key_selector_key_ops_valid?(_, _), do: true

  defp key_selector_kty_valid?(%{"kty" => kty}, %{kty: ktys}), do: kty in ktys
  defp key_selector_kty_valid?(_, _), do: true

  defp key_selector_alg_valid?(%{"alg" => alg}, %{alg: algs}) when is_list(algs), do: alg in algs
  defp key_selector_alg_valid?(jwk, %{alg: algs}) when is_list(algs),
    do: Enum.any?(algs, &(&1 in sig_algs_supported(jwk) or &1 in enc_algs_supported(jwk)))
  defp key_selector_alg_valid?(_, _), do: true

  defp key_selector_enc_valid?(%{"enc" => enc}, %{alg: encs}), do: enc in encs
  defp key_selector_enc_valid?(_, _), do: true

  defp key_selector_crv_valid?(%{"crv" => crv}, %{crv: crvs}), do: crv in crvs
  defp key_selector_crv_valid?(_, _), do: true

  @doc """
  Returns the digest used by a signature algorithm of the key
  """
  @spec sig_alg_digest(t()) :: atom()
  def sig_alg_digest(%{"alg" => "EdDSA", "crv" => "Ed25519"}), do: :sha256
  def sig_alg_digest(%{"alg" => "EdDSA", "crv" => "Ed448"}), do: :sha3_256
  def sig_alg_digest(%{"alg" => "ES256"}), do: :sha256
  def sig_alg_digest(%{"alg" => "ES384"}), do: :sah384
  def sig_alg_digest(%{"alg" => "ES512"}), do: :sha512
  def sig_alg_digest(%{"alg" => "HS256"}), do: :sha256
  def sig_alg_digest(%{"alg" => "HS384"}), do: :sha384
  def sig_alg_digest(%{"alg" => "HS512"}), do: :sha512
  def sig_alg_digest(%{"alg" => "PS256"}), do: :sha256
  def sig_alg_digest(%{"alg" => "PS384"}), do: :sha384
  def sig_alg_digest(%{"alg" => "PS512"}), do: :sha512
  def sig_alg_digest(%{"alg" => "RS256"}), do: :sha256
  def sig_alg_digest(%{"alg" => "RS384"}), do: :sha384
  def sig_alg_digest(%{"alg" => "RS512"}), do: :sha512

  @doc """
  Returns the public key from a private key

  For `"oct"` symmetrical keys, it returns all fields except the `"k"` private secret.
  It is recommended to have the `"kid"` attribute set in this case, otherwise the key
  is indistinguishable from other similar symmetrical keys.

  ## Examples

      iex> match?(%{"kty" => "EC", "crv" => "P-521"}, JOSE.JWK.generate_key({:ec, "P-521"}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.to_public())
      true

      iex> JOSE.JWK.generate_key({:oct, 32}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.to_public()                                                
      %{"kty" => "oct"}
  """
  @spec to_public(t()) :: t()
  def to_public(%{"kty" => "oct"} = jwk_oct) do
    Map.delete(jwk_oct, "k")
  end

  def to_public(jwk) do
    jwk
    |> JOSE.JWK.from_map()
    |> JOSE.JWK.to_public()
    |> JOSE.JWK.to_map()
    |> elem(1)
  end

  @doc """
  Returns the list of supported signature algorithms for a given JWK

  ## Example
  
      iex> JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.sig_algs_supported()
      ["ES256"]

      iex> JOSE.JWK.generate_key({:ec, "P-521"}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.sig_algs_supported()
      ["ES512"]

      iex> JOSE.JWK.generate_key({:oct, 32}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.sig_algs_supported()
      ["HS256"]

      iex> JOSE.JWK.generate_key({:oct, 48}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.sig_algs_supported()
      ["HS256", "HS384"]

      iex> JOSE.JWK.generate_key({:oct, 47}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.sig_algs_supported()
      ["HS256"]

      iex> JOSE.JWK.generate_key({:oct, 64}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.sig_algs_supported()
      ["HS256", "HS384", "HS512"]

      iex> JOSE.JWK.generate_key({:rsa,2048}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.sig_algs_supported()
      ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]

      iex> JOSE.crypto_fallback(true)
      iex> JOSE.JWK.generate_key({:okp, :Ed25519}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.sig_algs_supported()
      ["EdDSA"]
  """
  @spec sig_algs_supported(t()) :: [JWA.sig_alg()]
  def sig_algs_supported(%{"alg" => alg}), do: [alg]
  def sig_algs_supported(%{"kty" => "RSA"}),
    do: ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]
  def sig_algs_supported(%{"kty" => "EC", "crv" => "P-256"}), do: ["ES256"]
  def sig_algs_supported(%{"kty" => "EC", "crv" => "P-384"}), do: ["ES384"]
  def sig_algs_supported(%{"kty" => "EC", "crv" => "P-521"}), do: ["ES512"]
  def sig_algs_supported(%{"kty" => "EC", "crv" => "secp256k1"}), do: ["ES256K"]
  def sig_algs_supported(%{"kty" => "OKP", "crv" => "Ed25519"}), do: ["EdDSA"]
  def sig_algs_supported(%{"kty" => "OKP", "crv" => "Ed448"}), do: ["EdDSA"]
  def sig_algs_supported(%{"kty" => "oct", "k" => k}) do
    size_bits = k |> Base.url_decode64!(padding: false) |> byte_size() |> Kernel.*(8)

    cond do
      size_bits >= 512 -> ["HS256", "HS384", "HS512"]
      size_bits >= 384 -> ["HS256", "HS384"]
      size_bits >= 256 -> ["HS256"]
      true -> []
    end
  end
  def sig_algs_supported(%{"kty" => "oct"}), do: []
  def sig_algs_supported(_), do: []

  @doc """
  Returns the list of supported key derivation algorithm for a given JWK

  ## Examples
      iex> JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.enc_algs_supported()
      ["RSA1_5", "RSA-OAEP", "RSA-OAEP-256"]

      iex> JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.enc_algs_supported()
      ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]

      iex> JOSE.JWK.generate_key({:oct, 16}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.enc_algs_supported()
      ["A128KW", "A128GCMKW", "dir", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"]

      iex> JOSE.JWK.generate_key({:oct, 32}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.enc_algs_supported()
      ["A256KW", "A256GCMKW", "dir", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"]

      iex> JOSE.crypto_fallback(true)
      iex> JOSE.JWK.generate_key({:okp, :Ed25519}) |> JOSE.JWK.to_map() |> elem(1) |> JOSEUtils.JWK.enc_algs_supported()
      ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]
  """
  @spec enc_algs_supported(t()) :: [JWA.enc_alg()]
  def enc_algs_supported(%{"alg" => alg}), do: [alg]
  def enc_algs_supported(%{"kty" => "RSA"}), do: ["RSA1_5", "RSA-OAEP", "RSA-OAEP-256"]
  def enc_algs_supported(%{"kty" => kty}) when kty in ["EC", "OKP"],
    do: ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]
  def enc_algs_supported(%{"kty" => "oct", "k" => k}) do
    size_bits = k |> Base.url_decode64!(padding: false) |> byte_size() |> Kernel.*(8)

    cond do
      size_bits == 128 ->
        ["A128KW", "A128GCMKW", "dir", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW",
         "PBES2-HS512+A256KW"]

      size_bits == 192 ->
        ["A192KW", "A192GCMKW", "dir", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW",
         "PBES2-HS512+A256KW"]

      size_bits == 256 ->
        ["A256KW", "A256GCMKW", "dir", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW",
         "PBES2-HS512+A256KW"]

      true ->
        ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"]
    end
  end
  def enc_algs_supported(%{"kty" => "oct"}),
    do: ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"]
  def enc_algs_supported(_), do: []

  @doc """
  Verifies a JWK

  It performs the following checks:
  - verifies that the `"x5c"` member (if present) against:
    - the JWK key
    - the `"alg"` member
    - the `"use"` member
    - the `"key_ops"` member
    - the `"x5t"` member, if present
    - the `"x5t#S256"` member, if present
    - validates the certificate chain
  - verifies that the `"use"` and `"key_ops"` members are consistent
  - verifies that the `"key_ops"` operations are related to each other
  """

  @spec verify(t()) :: result()
  def verify(%{} = jwk) do
    with :ok <- is_jwk(jwk),
         :ok <- verify_x5c(jwk),
         :ok <- verify_x5t(jwk),
         :ok <- verify_x5t_s256(jwk),
         :ok <- verify_use_key_ops_consistent(jwk),
         :ok <- verify_key_ops_related(jwk) do
      :ok
    end
  end

  @spec is_jwk(t()) :: result()
  defp is_jwk(%{"kty" => kty}) when is_binary(kty), do: :ok
  defp is_jwk(_), do: {:error, :invalid_jwk}

  @spec verify_x5c(t()) :: result()
  defp verify_x5c(%{"x5c" => [_ | _]} = jwk) do
    with jose_jwk = JOSE.JWK.from_map(jwk),
         {:ok, leaf_cert_der} <- Base.decode64(List.first(jose_jwk.fields["x5c"])),
         {:ok, leaf_cert} <- X509.Certificate.from_der(leaf_cert_der),
         :ok <- verify_keys_verify(jose_jwk, leaf_cert),
         :ok <- verify_alg(jose_jwk, leaf_cert),
         :ok <- verify_use(jose_jwk, leaf_cert),
         :ok <- verify_key_ops(jose_jwk, leaf_cert),
         :ok <- verify_cert_chain(jose_jwk) do
      :ok
    else
      :error ->
        {:error, :x5c_invalid_base_64_encoding}

      {:error, _} = error ->
        error
    end
  rescue
    _ ->
      {:error, :invalid_jwk}
  end

  defp verify_x5c(%{"x5c" => _}) do
    {:error, :invalid_x5c_member}
  end

  defp verify_x5c(_) do
    :ok
  end

  @spec verify_keys_verify(%JOSE.JWK{}, certificate()) :: result()
  defp verify_keys_verify(jose_jwk, cert) do
    {:OTPCertificate,
     {:OTPTBSCertificate, _, _, _, _, _, _, {:OTPSubjectPublicKeyInfo, _, cert_key}, _, _, _}, _,
     _} = cert

    {_kty, jwk_key} = jose_jwk.kty

    if cert_key == jwk_key do
      :ok
    else
      {:error, :x5c_non_matching_keys}
    end
  end

  @spec verify_alg(%JOSE.JWK{}, certificate()) :: result()
  defp verify_alg(%JOSE.JWK{fields: %{"alg" => alg}}, cert) when is_binary(alg) do
    {
      :OTPCertificate,
      {:OTPTBSCertificate, _, _, {:SignatureAlgorithm, otp_sig_alg, _}, _, _, _, _, _, _, _},
      # both signatures must be equal
      {:SignatureAlgorithm, otp_sig_alg, _},
      _
    } = cert

    if JWA.x509_to_jose_sig_alg(otp_sig_alg) == alg do
      :ok
    else
      {:error, :x5c_non_matching_algs}
    end
  end

  defp verify_alg(_, _) do
    :ok
  end

  @spec verify_use(%JOSE.JWK{}, certificate()) :: result()
  defp verify_use(%JOSE.JWK{fields: %{"use" => key_usage}}, cert) do
    x509_key_usage =
      case key_usage do
        "sig" -> :digitalSignature
        "enc" -> :keyAgreement
      end

    case X509.Certificate.extension(cert, :key_usage) do
      {:Extension, {2, 5, 29, 15}, _, cert_usages} ->
        if x509_key_usage in cert_usages do
          :ok
        else
          {:error, :x5c_non_matching_key_usage}
        end

      _ ->
        :ok
    end
  end

  defp verify_use(_, _) do
    :ok
  end

  @spec verify_key_ops(%JOSE.JWK{}, certificate()) :: result()
  defp verify_key_ops(%JOSE.JWK{fields: %{"key_ops" => key_ops}}, cert) do
    if Enum.uniq(key_ops) == key_ops do
      case X509.Certificate.extension(cert, :key_usage) do
        {:Extension, {2, 5, 29, 15}, _, cert_usages} ->
          if Enum.all?(key_ops, &verify_key_op(&1, cert_usages)) do
            :ok
          else
            {:error, :x5c_non_matching_key_usage}
          end

        _ ->
          :ok
      end
    else
      {:error, :key_ops_non_unique_member}
    end
  end

  defp verify_key_ops(_, _) do
    :ok
  end

  @spec verify_key_ops_related(t()) :: result()
  defp verify_key_ops_related(%{"key_ops" => key_ops}) do
    key_ops
    |> Enum.sort()
    |> do_verify_key_ops_related()
  end

  defp verify_key_ops_related(_) do
    :ok
  end

  defp do_verify_key_ops_related([]), do: :ok
  defp do_verify_key_ops_related([_key_op]), do: :ok
  defp do_verify_key_ops_related(["sign", "verify"]), do: :ok
  defp do_verify_key_ops_related(["decrypt", "encrypt"]), do: :ok
  defp do_verify_key_ops_related(["unwrapKey", "wrapKey"]), do: :ok
  defp do_verify_key_ops_related(_), do: {:error, :key_ops_unrelated_ops}

  @spec verify_key_op(String.t(), [atom()]) :: boolean()
  defp verify_key_op(key_op, cert_usages) do
    case key_op do
      "sign" -> :digitalSignature in cert_usages
      "verify" -> :digitalSignature in cert_usages
      "encrypt" -> :keyEncipherment in cert_usages
      "decrypt" -> :keyEncipherment in cert_usages
      "wrapKey" -> :keyEncipherment in cert_usages
      "unwrapKey" -> :keyEncipherment in cert_usages
      "deriveKey" -> true
      "deriveBits" -> true
      _ -> true
    end
  end

  @spec verify_use_key_ops_consistent(t()) :: result()

  defp verify_use_key_ops_consistent(%{"use" => "sign", "key_ops" => key_ops}) do
    if Enum.sort(key_ops) in [["sign"], ["verify"], ["sign", "verify"]] do
      :ok
    else
      {:error, :inconsistent_use_and_key_ops_members}
    end
  end

  defp verify_use_key_ops_consistent(%{"use" => "enc", "key_ops" => key_ops}) do
    (Enum.sort(key_ops) in [
       ["encrypt"],
       ["decrypt"],
       ["decrypt", "encrypt"],
       ["wrapKey"],
       ["unwrapKey"],
       ["unwrapKey", "wrapKey"]
     ])
    |> if do
      :ok
    else
      {:error, :inconsistent_use_and_key_ops_members}
    end
  end

  defp verify_use_key_ops_consistent(_) do
    :ok
  end

  @spec verify_cert_chain(%JOSE.JWK{}) :: result()
  defp verify_cert_chain(%JOSE.JWK{fields: %{"x5c" => [_]}}) do
    :ok
  end

  defp verify_cert_chain(%JOSE.JWK{fields: %{"x5c" => cert_chain}}) do
    certs =
      cert_chain
      |> Enum.map(&Base.decode64!/1)
      |> Enum.reverse()

    case :public_key.pkix_path_validation(List.first(certs), certs, []) do
      {:ok, _} ->
        :ok

      {:error, _} ->
        {:error, :x5c_failed_path_validation}
    end
  rescue
    _ ->
      {:error, :x5c_invalid_base64_encoding}
  end

  @spec verify_x5t(t()) :: result()
  defp verify_x5t(%{"x5t" => x5t_b64, "x5c" => [leaf_cert_b64_der | _]}) do
    x5t = Base.url_decode64!(x5t_b64, padding: false)
    leaf_cert_der = Base.decode64!(leaf_cert_b64_der)

    if :crypto.hash(:sha, leaf_cert_der) == x5t do
      :ok
    else
      {:error, :x5t_invalid_certificate_hash}
    end
  rescue
    _ ->
      {:error, :x5t_invalid_base64_encoding}
  end

  defp verify_x5t(_) do
    :ok
  end

  @spec verify_x5t_s256(t()) :: result()
  defp verify_x5t_s256(%{"x5t#S256" => x5t_s256_b64, "x5c" => [leaf_cert_b64_der | _]}) do
    x5t_s256 = Base.url_decode64!(x5t_s256_b64, padding: false)
    leaf_cert_der = Base.decode64!(leaf_cert_b64_der)

    if :crypto.hash(:sha256, leaf_cert_der) == x5t_s256 do
      :ok
    else
      {:error, :x5t_s256_invalid_certificate_hash}
    end
  rescue
    _ ->
      {:error, :x5ts256_invalid_base64_encoding}
  end

  defp verify_x5t_s256(_) do
    :ok
  end
end
