defmodule JOSEUtils.JWK do
  @moduledoc """
  Util functions to work with JWKs
  """

  @typedoc """
  A JSON Web Key, such as:

      %{
        "crv" => "P-256",
        "kty" => "EC",
        "x" => "6pwDpICQ8JBWdvuLuXeWILAxSEUNB_BBAswikgYKKmY",
        "y" => "fEHj1ehsIJ7PP-qon-oONl_J2yZLWpUncNRedZT7xqs"
      }
  """
  @type t :: %{required(String.t()) => any()}

  @type alg :: String.t()

  # X509.Certificate.t()
  @type certificate :: any()

  @type result :: :ok | {:error, atom()}

  @doc """
  Returns the digest used by a signature algorithm of the key
  """
  # :crypto.hash_algorithm()
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
    with :ok <- verify_x5c(jwk),
         :ok <- verify_x5t(jwk),
         :ok <- verify_x5t_s256(jwk),
         :ok <- verify_use_key_ops_consistent(jwk),
         :ok <- verify_key_ops_related(jwk) do
      :ok
    end
  end

  # FIXME: should be check certificate expiration?

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

    if to_jose_alg(otp_sig_alg) == alg do
      :ok
    else
      {:error, :x5c_non_matching_algs}
    end
  end

  defp verify_alg(_, _) do
    :ok
  end

  @spec to_jose_alg(tuple()) :: String.t() | nil
  defp to_jose_alg({1, 2, 840, 113_549, 1, 1, 11}), do: "RS256"
  defp to_jose_alg({1, 2, 840, 113_549, 1, 1, 12}), do: "RS384"
  defp to_jose_alg({1, 2, 840, 113_549, 1, 1, 13}), do: "RS512"
  defp to_jose_alg({1, 2, 840, 10045, 4, 3, 2}), do: "ES256"
  defp to_jose_alg({1, 2, 840, 10045, 4, 3, 3}), do: "ES384"
  defp to_jose_alg({1, 2, 840, 10045, 4, 3, 4}), do: "ES512"
  defp to_jose_alg({1, 2, 840, 113_549, 1, 1, 5}), do: "RSA1_5"
  defp to_jose_alg(_), do: nil

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
