defmodule JOSEUtils.JWE do
  @moduledoc """
  Util function to work with encrypted JWTs
  """

  @typedoc """
  Serialized JWE encrypted token, for instance:

      "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJzODNFNjhPNjhsWlM5ZVprIiwidGFnIjoieF9Ea2M5dm1LMk5RQV8tU2hvTkFRdyJ9.8B2qX8fVEa-s61RsZXqkCg.J7yJ8sKLbUlzyor6.FRs.BhBwImTv9B14NwVuxmfU6A"
  """
  @type serialized :: String.t()

  @doc """
  Returns `true` if the string is an encrypted, `false` otherwise

  ## Example

      iex> jwe_token = "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJzODNFNjhPNjhsWlM5ZVprIiwidGFnIjoieF9Ea2M5dm1LMk5RQV8tU2hvTkFRdyJ9.8B2qX8fVEa-s61RsZXqkCg.J7yJ8sKLbUlzyor6.FRs.BhBwImTv9B14NwVuxmfU6A"
      "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJzODNFNjhPNjhsWlM5ZVprIiwidGFnIjoieF9Ea2M5dm1LMk5RQV8tU2hvTkFRdyJ9.8B2qX8fVEa-s61RsZXqkCg.J7yJ8sKLbUlzyor6.FRs.BhBwImTv9B14NwVuxmfU6A"
      iex> JOSEUtils.JWE.is_encrypted_jwt?(jwe_token)
      true

      iex> jws_token = "eyJhbGciOiJFZDI1NTE5In0.e30.xyg2LTblm75KbLFJtROZRhEgAFJdlqH9bhx8a9LO1yvLxNLhO9fLqnFuU3ojOdbObr8bsubPkPqUfZlPkGHXCQ"
      "eyJhbGciOiJFZDI1NTE5In0.e30.xyg2LTblm75KbLFJtROZRhEgAFJdlqH9bhx8a9LO1yvLxNLhO9fLqnFuU3ojOdbObr8bsubPkPqUfZlPkGHXCQ"
      iex> JOSEUtils.JWE.is_encrypted_jwt?(jws_token)
      false
  """

  @spec is_encrypted_jwt?(String.t()) :: boolean()
  def is_encrypted_jwt?(input) when is_binary(input) do
    JOSE.JWE.expand(input)

    true
  rescue
    _ ->
    false
  end

  @doc """
  Decrypts a JWE encrypted token and returns the decryption key
  """
  @spec decrypt(
    jwe :: serialized(),
    jwk_or_jwks :: JOSEUtils.JWK.t() | [JOSEUtils.JWK.t()],
    allowed_algs :: [JOSEUtils.JWA.enc_alg()],
    allowed_encs :: [JOSEUtils.JWA.enc_enc()]
  ) :: {:ok, {decrypted_message :: binary(), JOSEUtils.JWK.t()}} | :error
  def decrypt(jwe, %{} = jwk, allowed_algs, allowed_encs) do
    decrypt(jwe, [jwk], allowed_algs, allowed_encs)
  end

  def decrypt(jwe, jwks, allowed_algs, allowed_encs) do
    case String.split(jwe, ".") do
      [header_b64, _, _, _, _] ->
        with {:ok, header_str} <- Base.decode64(header_b64, padding: false),
             {:ok, header} <- Jason.decode(header_str),
             true <- header["alg"] in allowed_algs,
             true <- header["enc"] in allowed_encs
        do
          jwks =
            case header do
              %{"alg" => _, "kid" => jwe_kid} ->
                Enum.filter(jwks, fn jwk -> jwk["kid"] == jwe_kid end)

              _ ->
                jwks
            end
            |> JOSEUtils.JWKS.decryption_keys(header["alg"], header["enc"])

          do_decrypt(jwe, header, jwks)
        else
          _ ->
            :error
        end

      _ ->
        :error
    end
  end

  @spec do_decrypt(
    serialized(),
    map(),
    JOSEUtils.JWK.t() | [JOSEUtils.JWK.t()]
  ) :: {:ok, {binary(), JOSEUtils.JWK.t()}} | :error
  defp do_decrypt(jwe, header, %{} = jwk) do
    case JOSE.JWE.block_decrypt(jwk, jwe) do
      {message, %JOSE.JWE{} = jose_jwe} when is_binary(message) ->
        if jose_alg(jose_jwe) == header["alg"] and jose_enc(jose_jwe) == header["enc"] do
          {:ok, {message, jwk}}
        else
          :error
        end

      {:error, %JOSE.JWE{}} ->
        :error
    end
  end

  defp do_decrypt(jwe, header, jwks) when is_list(jwks) do
    Enum.find_value(
      jwks,
      :error,
      fn jwk ->
        case do_decrypt(jwe, header, jwk) do
          {:ok, _} = result ->
            result

          :error ->
            false
        end
      end
    )
  end

  @doc """
  Returns the JOSE algorithm name from a `%JOSE.JWE{}` structure

      iex> jwk_oct128 = JOSE.JWK.from_oct(<<0::128>>)
      %JOSE.JWK{
        fields: %{},
        keys: :undefined,
        kty: {:jose_jwk_kty_oct, <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>}
      }
      iex> encrypted_a128gcmkw = JOSE.JWE.block_encrypt(jwk_oct128, "{}", %{ "alg" => "A128GCMKW", "enc" => "A128GCM" }) |> JOSE.JWE.compact |> elem(1)
      "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJkOERDUHI3Z0NNSmZhVE8zIiwidGFnIjoiTVlkOUlkM3BzcmpfbjFlalUxQlk2ZyJ9.Rwcs6_ZukJBWJka1k8zSlw.EzrsnOl0dUPQ7U3G.7Q0.tRU9DCY6zmNBseObLku8Xw"
      iex> JOSE.JWE.block_decrypt(jwk_oct128, encrypted_a128gcmkw) |> elem(1) |> JOSEUtils.JWE.jose_alg()
      "A128GCMKW"
  """
  @spec jose_alg(%JOSE.JWE{}) :: JOSEUtils.JWA.enc_alg()
  def jose_alg(
    %JOSE.JWE{alg: {:jose_jwe_alg_aes_kw, {:jose_jwe_alg_aes_kw, 128, true, _, _}}}
  ) do
    "A128GCMKW"
  end

  def jose_alg(
    %JOSE.JWE{alg: {:jose_jwe_alg_aes_kw, {:jose_jwe_alg_aes_kw, 128, false, _, _}}}
  ) do
    "A128KW"
  end

  def jose_alg(
    %JOSE.JWE{alg: {:jose_jwe_alg_aes_kw, {:jose_jwe_alg_aes_kw, 192, true, _, _}}}
  ) do
    "A192GCMKW"
  end

  def jose_alg(
    %JOSE.JWE{alg: {:jose_jwe_alg_aes_kw, {:jose_jwe_alg_aes_kw, 192, false, _, _}}}
  ) do
    "A192KW"
  end

  def jose_alg(
    %JOSE.JWE{alg: {:jose_jwe_alg_aes_kw, {:jose_jwe_alg_aes_kw, 256, true, _, _}}}
  ) do
    "A256GCMKW"
  end

  def jose_alg(
    %JOSE.JWE{alg: {:jose_jwe_alg_aes_kw, {:jose_jwe_alg_aes_kw, 256, false, _, _}}}
  ) do
    "A256KW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_ecdh_es,
        {:jose_jwe_alg_ecdh_es, _, _, _, :aes_gcm_kw, 128, _, _}
      }
    }
  ) do
    "ECDH-ES+A128GCMKW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_ecdh_es,
        {:jose_jwe_alg_ecdh_es, _, _, _, :aes_kw, 128, _, _}
      }
    }
  ) do
    "ECDH-ES+A128KW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_ecdh_es,
        {:jose_jwe_alg_ecdh_es, _, _, _, :aes_gcm_kw, 192, _, _}
      }
    }
  ) do
    "ECDH-ES+A192GCMKW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_ecdh_es,
        {:jose_jwe_alg_ecdh_es, _, _, _, :aes_kw, 192, _, _}
      }
    }
  ) do
    "ECDH-ES+A192KW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_ecdh_es,
        {:jose_jwe_alg_ecdh_es, _, _, _, :aes_gcm_kw, 256, _, _}
      }
    }
  ) do
    "ECDH-ES+A256GCMKW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_ecdh_es,
        {:jose_jwe_alg_ecdh_es, _, _, _, :aes_kw, 256, _, _}
      }
    }
  ) do
    "ECDH-ES+A256KW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_ecdh_es,
        {:jose_jwe_alg_ecdh_es, _, _, _, :c20p_kw, 256, _, _}
      }
    }
  ) do
    "ECDH-ES+C20PKW"
  end

  def jose_alg(
    %JOSE.JWE{alg: {:jose_jwe_alg_ecdh_es, {:jose_jwe_alg_ecdh_es, _, _, _, _, _, _, _}}}
  ) do
    "ECDH-ES"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_pbes2,
        {:jose_jwe_alg_pbes2, :sha256, _, 4096, :aes_gcm_kw, 128, _, _}
      }
    }
  ) do
    "PBES2-HS256+A128GCMKW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_pbes2,
        {:jose_jwe_alg_pbes2, :sha256, _, 4096, :aes_kw, 128, _, }
      }
    }
  ) do
    "PBES2-HS256+A128KW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_pbes2,
        {:jose_jwe_alg_pbes2, :sha384, _, 6144, :aes_gcm_kw, 192, _, _}
      }
    }
  ) do
    "PBES2-HS384+A192GCMKW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_pbes2,
        {:jose_jwe_alg_pbes2, :sha384, _, 6144, :aes_kw, 192, _, _}
      }
    }
  ) do
    "PBES2-HS384+A192KW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_pbes2,
        {:jose_jwe_alg_pbes2, :sha512, _, 8192, :aes_gcm_kw, 256, _, _}
      }
    }
  ) do
    "PBES2-HS512+A256GCMKW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_pbes2,
        {:jose_jwe_alg_pbes2, :sha512, _, 8192, :aes_kw, 256, _, _}
      }
    }
  ) do
    "PBES2-HS512+A256KW"
  end

  def jose_alg(
    %JOSE.JWE{alg:
      {:jose_jwe_alg_pbes2,
        {:jose_jwe_alg_pbes2, :sha512,_, 8192, :c20p_kw, 256, _, _}
      }
    }
  ) do
    "PBES2-HS512+C20PKW"
  end

  def jose_alg(%JOSE.JWE{alg: {:jose_jwe_alg_rsa, {:jose_jwe_alg_rsa, :rsa_oaep}}}) do
    "RSA-OAEP"
  end

  def jose_alg(%JOSE.JWE{alg: {:jose_jwe_alg_rsa, {:jose_jwe_alg_rsa, :rsa_oaep_256}}}) do
    "RSA-OAEP-256"
  end

  def jose_alg(%JOSE.JWE{alg: {:jose_jwe_alg_rsa, {:jose_jwe_alg_rsa, :rsa1_5}}}) do
    "RSA1_5"
  end

  def jose_alg(%JOSE.JWE{alg: {:jose_jwe_alg_dir, :dir}}) do
    "dir"
  end

  @doc """
  Returns the JOSE encryption algorithm name from a `%JOSE.JWE{}` structure
  """
  @spec jose_enc(%JOSE.JWE{}) :: JOSEUtils.JWA.enc_enc()
  def jose_enc(
    %JOSE.JWE{enc:
      {:jose_jwe_enc_aes,
        {:jose_jwe_enc_aes, {:aes_cbc, 128}, 256, _, _, _, _, _, :sha256}
      }
    }
  ) do
    "A128CBC-HS256"
  end

  def jose_enc(
    %JOSE.JWE{enc:
      {:jose_jwe_enc_aes, {:jose_jwe_enc_aes, {:aes_gcm, 128}, 128, _, _, _, _, _, _}}
    }
  ) do
    "A128GCM"
  end

  def jose_enc(
    %JOSE.JWE{enc:
      {:jose_jwe_enc_aes,
        {:jose_jwe_enc_aes, {:aes_cbc, 192}, 384, _, _, _, _, _, :sha384}
      }
    }
  ) do
    "A192CBC-HS384"
  end

  def jose_enc(
    %JOSE.JWE{enc:
      {:jose_jwe_enc_aes, {:jose_jwe_enc_aes, {:aes_gcm, 192}, 192, _, _, _, _, _, _}}
    }
  ) do
    "A192GCM"
  end

  def jose_enc(
    %JOSE.JWE{enc:
      {:jose_jwe_enc_aes,
        {:jose_jwe_enc_aes, {:aes_cbc, 256}, 512, _, _, _, _, _, :sha512}
      }
    }
  ) do
    "A256CBC-HS512"
  end

  def jose_enc(
    %JOSE.JWE{enc:
      {:jose_jwe_enc_aes, {:jose_jwe_enc_aes, {:aes_gcm, 256}, 256, _, _, _, _, _, _}}
    }
  ) do
    "A256GCM"
  end

  def jose_enc(%JOSE.JWE{enc: {:jose_jwe_enc_c20p, {:chacha20_poly1305, 256}}}) do
    "C20P"
  end

  def jose_enc(%JOSE.JWE{enc: {:jose_jwe_enc_xc20p, {:xchacha20_poly1305, 256}}}) do
    "XC20P"
  end
end
