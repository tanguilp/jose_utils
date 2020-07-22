defmodule JOSEUtils.JWE do
  @moduledoc """
  Convenience function to work with encrypted JWTs
  """

  alias JOSEUtils.{JWA, JWK}

  @typedoc """
  Serialized JWE encrypted token

  For instance:

      "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJzODNFNjhPNjhsWlM5ZVprIiwidGFnIjoieF9Ea2M5dm1LMk5RQV8tU2hvTkFRdyJ9.8B2qX8fVEa-s61RsZXqkCg.J7yJ8sKLbUlzyor6.FRs.BhBwImTv9B14NwVuxmfU6A"
  """
  @type serialized :: String.t()

  @ecdh_algs ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]

  defmodule MalformedError do
    defexception message: "malformed JWE"
  end

  @doc """
  Returns the unverified header

  It ensures that the `"alg"` and `"enc"` mandatory parameters are present.

  ## Examples

      iex> JOSEUtils.JWE.peek_header("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..jBt5tTa1Q0N3uFPEkf30MQ.Ei49MvTLLje7bsZ5EZCZMA.gMWOAmhZSq9ksHCZm6VSoA")
      {:ok, %{"alg" => "dir", "enc" => "A128CBC-HS256"}}

      iex> JOSEUtils.JWE.peek_header("this is obviously invalid")
      {:error, %JOSEUtils.JWE.MalformedError{message: "malformed JWE"}}
  """
  @spec peek_header(serialized()) ::
  {:ok, %{optional(String.t()) => any()}} | {:error, Exception.t()}
  def peek_header(<<_::binary>> = jwe) do
    with {_, expanded} = JOSE.JWE.expand(jwe),
         protected_b64 = Map.get(expanded, "protected"),
         {:ok, protected_str} = Base.url_decode64(protected_b64, padding: false) do
      {:ok, %{"alg" => _, "enc" => _}} = Jason.decode(protected_str)
    end
  rescue
    _ ->
      {:error, %MalformedError{}}
  end

  @doc """
  Encrypts a payload with a JWK given an key derivation algorithm and an encryption
  algorithm

  The payload can be a string, in which case it is signed directly, or any other data type
  which will first be converted into text using JSON serialization.

  If the JWK has a key id ("kid" member), it is automatically added to the resulting JWS.
  """
  @spec encrypt(
    payload :: any(),
    JWK.t() | {JWK.t(), JWK.t()},
    JWA.enc_alg(),
    JWA.enc_enc(),
    header :: %{optional(String.t()) => any()}
  ) :: {:ok, serialized()} | {:error, Exception.t()}
  def encrypt(payload, jwk, alg, enc, additional_headers \\ %{}) do
    {:ok, encrypt!(payload, jwk, alg, enc, additional_headers)}
  rescue
    e ->
      {:error, e}
  end

  @spec encrypt!(
    payload :: any(),
    JWK.t() | {JWK.t(), JWK.t()},
    JWA.enc_alg(),
    JWA.enc_enc(),
    header :: %{optional(String.t()) => any()}
  ) :: serialized()
  def encrypt!(payload, jwk, alg, enc, additional_headers \\ %{})

  def encrypt!(payload, %{"kid" => kid} = jwk, alg, enc, additional_headers),
    do: do_encrypt!(payload, jwk, alg, enc, Map.put(additional_headers, "kid", kid))
  def encrypt!(payload, jwk, alg, enc, additional_headers),
    do: do_encrypt!(payload, jwk, alg, enc, additional_headers)

  defp do_encrypt!(<<_::binary>> = payload, %{} = jwk, alg, enc, additional_headers) do
    jwk
    |> JOSE.JWK.from_map()
    |> JOSE.JWE.block_encrypt(
      payload,
      Map.merge(additional_headers, %{"alg" => alg, "enc" => enc})
    )
    |> JOSE.JWE.compact()
    |> elem(1)
  end

  defp do_encrypt!(<<_::binary>> = payload, {jwk_sk, jwk_pk}, alg, enc, additional_headers)
    when alg in @ecdh_algs
  do
    jwk_sk = JOSE.JWK.from_map(jwk_sk)
    jwk_pk = JOSE.JWK.from_map(jwk_pk)

    JOSE.JWE.block_encrypt(
      {jwk_sk, jwk_pk},
      payload,
      Map.merge(additional_headers, %{"alg" => alg, "enc" => enc})
    )
    |> JOSE.JWE.compact()
    |> elem(1)
  end

  defp do_encrypt!(payload, jwk, alg, enc, additional_headers) do
    payload
    |> Jason.encode!()
    |> encrypt!(jwk, alg, enc, additional_headers)
  end

  @doc """
  Decrypts a JWE encrypted token and returns the decryption key

  It filters the keys to select only those suitable for decryption, using
  `JOSEUtils.JWKS.decryption_keys/3`. If the JWE has an identifier (`"kid"`), it only uses
  that specific key.

  ## Example
      iex> jwk_oct256 = JOSE.JWK.from_oct(<<0::256>>)
      iex> jwk_oct256_map = JOSE.JWK.from_oct(<<0::256>>) |> JOSE.JWK.to_map() |> elem(1)
      iex> encrypted_a256gcmkw = JOSE.JWE.block_encrypt(jwk_oct256, "{}", %{ "alg" => "A256GCMKW", "enc" => "A256GCM" }) |> JOSE.JWE.compact |> elem(1)
      iex> JOSEUtils.JWE.decrypt(encrypted_a256gcmkw, jwk_oct256_map, ["A256KW"], ["A256GCM"])
      :error
      iex> JOSEUtils.JWE.decrypt(encrypted_a256gcmkw, jwk_oct256_map, ["A256KW", "A256GCMKW"], ["A256GCM"])
      {:ok, {"{}", %{"kty" => "oct"}}}
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
    with {:ok, header} <- peek_header(jwe),
         true <- header["alg"] in allowed_algs,
         true <- header["enc"] in allowed_encs do
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
  rescue
    _ ->
      :error
  end

  @spec do_decrypt(
          serialized(),
          map(),
          JOSEUtils.JWK.t() | [JOSEUtils.JWK.t()]
        ) :: {:ok, {binary(), JOSEUtils.JWK.t()}} | :error
  defp do_decrypt(jwe, header, %{} = jwk) do
    case JOSE.JWE.block_decrypt(JOSE.JWK.from_map(jwk), jwe) do
      {message, %JOSE.JWE{} = jose_jwe} when is_binary(message) ->
        if jose_alg(jose_jwe) == header["alg"] and jose_enc(jose_jwe) == header["enc"] do
          {:ok, {message, JWK.to_public(jwk)}}
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
      iex> encrypted_a128gcmkw = JOSE.JWE.block_encrypt(jwk_oct128, "{}", %{ "alg" => "A128GCMKW", "enc" => "A128GCM" }) |> JOSE.JWE.compact |> elem(1)
      iex> JOSE.JWE.block_decrypt(jwk_oct128, encrypted_a128gcmkw) |> elem(1) |> JOSEUtils.JWE.jose_alg()
      "A128GCMKW"
  """
  @spec jose_alg(%JOSE.JWE{}) :: JOSEUtils.JWA.enc_alg()
  def jose_alg(%JOSE.JWE{alg: {:jose_jwe_alg_aes_kw, {:jose_jwe_alg_aes_kw, 128, true, _, _}}}) do
    "A128GCMKW"
  end

  def jose_alg(%JOSE.JWE{alg: {:jose_jwe_alg_aes_kw, {:jose_jwe_alg_aes_kw, 128, false, _, _}}}) do
    "A128KW"
  end

  def jose_alg(%JOSE.JWE{alg: {:jose_jwe_alg_aes_kw, {:jose_jwe_alg_aes_kw, 192, true, _, _}}}) do
    "A192GCMKW"
  end

  def jose_alg(%JOSE.JWE{alg: {:jose_jwe_alg_aes_kw, {:jose_jwe_alg_aes_kw, 192, false, _, _}}}) do
    "A192KW"
  end

  def jose_alg(%JOSE.JWE{alg: {:jose_jwe_alg_aes_kw, {:jose_jwe_alg_aes_kw, 256, true, _, _}}}) do
    "A256GCMKW"
  end

  def jose_alg(%JOSE.JWE{alg: {:jose_jwe_alg_aes_kw, {:jose_jwe_alg_aes_kw, 256, false, _, _}}}) do
    "A256KW"
  end

  def jose_alg(%JOSE.JWE{
        alg: {:jose_jwe_alg_ecdh_es, {:jose_jwe_alg_ecdh_es, _, _, _, :aes_gcm_kw, 128, _, _}}
      }) do
    "ECDH-ES+A128GCMKW"
  end

  def jose_alg(%JOSE.JWE{
        alg: {:jose_jwe_alg_ecdh_es, {:jose_jwe_alg_ecdh_es, _, _, _, :aes_kw, 128, _, _}}
      }) do
    "ECDH-ES+A128KW"
  end

  def jose_alg(%JOSE.JWE{
        alg: {:jose_jwe_alg_ecdh_es, {:jose_jwe_alg_ecdh_es, _, _, _, :aes_gcm_kw, 192, _, _}}
      }) do
    "ECDH-ES+A192GCMKW"
  end

  def jose_alg(%JOSE.JWE{
        alg: {:jose_jwe_alg_ecdh_es, {:jose_jwe_alg_ecdh_es, _, _, _, :aes_kw, 192, _, _}}
      }) do
    "ECDH-ES+A192KW"
  end

  def jose_alg(%JOSE.JWE{
        alg: {:jose_jwe_alg_ecdh_es, {:jose_jwe_alg_ecdh_es, _, _, _, :aes_gcm_kw, 256, _, _}}
      }) do
    "ECDH-ES+A256GCMKW"
  end

  def jose_alg(%JOSE.JWE{
        alg: {:jose_jwe_alg_ecdh_es, {:jose_jwe_alg_ecdh_es, _, _, _, :aes_kw, 256, _, _}}
      }) do
    "ECDH-ES+A256KW"
  end

  def jose_alg(%JOSE.JWE{
        alg: {:jose_jwe_alg_ecdh_es, {:jose_jwe_alg_ecdh_es, _, _, _, :c20p_kw, 256, _, _}}
      }) do
    "ECDH-ES+C20PKW"
  end

  def jose_alg(%JOSE.JWE{
        alg: {:jose_jwe_alg_ecdh_es, {:jose_jwe_alg_ecdh_es, _, _, _, _, _, _, _}}
      }) do
    "ECDH-ES"
  end

  def jose_alg(%JOSE.JWE{
        alg:
          {:jose_jwe_alg_pbes2, {:jose_jwe_alg_pbes2, :sha256, _, 4096, :aes_gcm_kw, 128, _, _}}
      }) do
    "PBES2-HS256+A128GCMKW"
  end

  def jose_alg(%JOSE.JWE{
        alg: {:jose_jwe_alg_pbes2, {:jose_jwe_alg_pbes2, :sha256, _, 4096, :aes_kw, 128, _}}
      }) do
    "PBES2-HS256+A128KW"
  end

  def jose_alg(%JOSE.JWE{
        alg:
          {:jose_jwe_alg_pbes2, {:jose_jwe_alg_pbes2, :sha384, _, 6144, :aes_gcm_kw, 192, _, _}}
      }) do
    "PBES2-HS384+A192GCMKW"
  end

  def jose_alg(%JOSE.JWE{
        alg: {:jose_jwe_alg_pbes2, {:jose_jwe_alg_pbes2, :sha384, _, 6144, :aes_kw, 192, _, _}}
      }) do
    "PBES2-HS384+A192KW"
  end

  def jose_alg(%JOSE.JWE{
        alg:
          {:jose_jwe_alg_pbes2, {:jose_jwe_alg_pbes2, :sha512, _, 8192, :aes_gcm_kw, 256, _, _}}
      }) do
    "PBES2-HS512+A256GCMKW"
  end

  def jose_alg(%JOSE.JWE{
        alg: {:jose_jwe_alg_pbes2, {:jose_jwe_alg_pbes2, :sha512, _, 8192, :aes_kw, 256, _, _}}
      }) do
    "PBES2-HS512+A256KW"
  end

  def jose_alg(%JOSE.JWE{
        alg: {:jose_jwe_alg_pbes2, {:jose_jwe_alg_pbes2, :sha512, _, 8192, :c20p_kw, 256, _, _}}
      }) do
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
  def jose_enc(%JOSE.JWE{
        enc:
          {:jose_jwe_enc_aes, {:jose_jwe_enc_aes, {:aes_cbc, 128}, 256, _, _, _, _, _, :sha256}}
      }) do
    "A128CBC-HS256"
  end

  def jose_enc(%JOSE.JWE{
        enc: {:jose_jwe_enc_aes, {:jose_jwe_enc_aes, {:aes_gcm, 128}, 128, _, _, _, _, _, _}}
      }) do
    "A128GCM"
  end

  def jose_enc(%JOSE.JWE{
        enc:
          {:jose_jwe_enc_aes, {:jose_jwe_enc_aes, {:aes_cbc, 192}, 384, _, _, _, _, _, :sha384}}
      }) do
    "A192CBC-HS384"
  end

  def jose_enc(%JOSE.JWE{
        enc: {:jose_jwe_enc_aes, {:jose_jwe_enc_aes, {:aes_gcm, 192}, 192, _, _, _, _, _, _}}
      }) do
    "A192GCM"
  end

  def jose_enc(%JOSE.JWE{
        enc:
          {:jose_jwe_enc_aes, {:jose_jwe_enc_aes, {:aes_cbc, 256}, 512, _, _, _, _, _, :sha512}}
      }) do
    "A256CBC-HS512"
  end

  def jose_enc(%JOSE.JWE{
        enc: {:jose_jwe_enc_aes, {:jose_jwe_enc_aes, {:aes_gcm, 256}, 256, _, _, _, _, _, _}}
      }) do
    "A256GCM"
  end

  def jose_enc(%JOSE.JWE{enc: {:jose_jwe_enc_c20p, {:chacha20_poly1305, 256}}}) do
    "C20P"
  end

  def jose_enc(%JOSE.JWE{enc: {:jose_jwe_enc_xc20p, {:xchacha20_poly1305, 256}}}) do
    "XC20P"
  end
end
