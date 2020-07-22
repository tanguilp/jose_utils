defmodule JOSEUtils.JWS do
  @moduledoc """
  Convenience functions to work with signed JWTs
  """

  alias JOSEUtils.{JWA, JWK}

  @typedoc """
  Serialized JWS signed token

  For instance:

      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
  """
  @type serialized :: String.t()

  defmodule MalformedError do
    defexception message: "malformed JWS"
  end

  @doc """
  Returns the unverified header

  It ensures the `"alg"` parameter is set.

  ## Example

      iex> JOSEUtils.JWS.peek_header("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.dMAojPMVbFvvkouYUSI9AxIRBxgqretQMCvNF7KmTHU")
      {:ok, %{"alg" => "HS256", "typ" => "JWT"}}

      iex> JOSEUtils.JWS.peek_header("probably invalid...?")
      {:error, %JOSEUtils.JWS.MalformedError{message: "malformed JWS"}}
  """
  @spec peek_header(serialized()) ::
  {:ok, %{optional(String.t()) => any()}} | {:error, Exception.t()}
  def peek_header(<<_::binary>> = jws) do
    protected_str = JOSE.JWS.peek_protected(jws)

    {:ok, %{"alg" => _}} = Jason.decode(protected_str)
  rescue
    _ ->
      {:error, %MalformedError{}}
  end

  @doc """
  Returns `:mac` if the JWS uses a MAC signature algoithm, `:public_key_crypto` otherwise

  ## Example

      iex> JOSE.JWS.sign(JOSE.JWK.generate_key({:ec, "P-256"}), "toto", %{"alg" => "ES256"})
      ...> |> JOSE.JWS.compact()
      ...> |> elem(1)
      ...> |> JOSEUtils.JWS.sig_alg_type()
      :public_key_crypto

      iex> JOSE.JWS.sign(JOSE.JWK.generate_key({:oct, 32}), "toto", %{"alg" => "HS256"})
      ...> |> JOSE.JWS.compact()
      ...> |> elem(1)
      ...> |> JOSEUtils.JWS.sig_alg_type()
      :mac

  """
  @spec sig_alg_type(serialized()) :: :public_key_crypto | :mac
  def sig_alg_type(<<_::binary>> = jws) do
    jws
    |> JOSE.JWS.peek_protected()
    |> Jason.decode!()
    |> case do
      %{"alg" => alg} when alg in ["HS256", "HS384", "HS512"] ->
        :mac

      _ ->
        :public_key_crypto
    end
  end

  @doc """
  Signs a payload with a JWK and a given signing algorithm

  The payload can be a string, in which case it is signed directly, or any other data type
  which will first be converted into text using JSON serialization.

  If the JWK has a key id ("kid" member), it is automatically added to the resulting JWS.

  ## Example

      iex> jwk = %{"k" => "FWTNVgrQyQyZmduoAVyOfI1myMs", "kty" => "oct"}
      iex> JOSEUtils.JWS.sign("some text", jwk, "HS256")
      {:ok, "eyJhbGciOiJIUzI1NiJ9.c29tZSB0ZXh0.2L2wNRpAOw92LSAII2PQ9_y9zi2YD9NfjJuGBpNkVBE"}
  """
  @spec sign(
    payload :: any(),
    JWK.t(),
    JWA.sig_alg(),
    additional_headers :: %{optional(String.t()) => any()}
  ) :: {:ok, serialized()} | {:error, Exception.t()}
  def sign(payload, jwk, sig_alg, additional_headers \\ %{}) do
    {:ok, sign!(payload, jwk, sig_alg, additional_headers)}
  rescue
    e ->
      {:error, e}
  end

  @doc """
  See `sign/4`
  """
  @spec sign!(
    payload :: any(),
    JWK.t(),
    JWA.sig_alg(),
    header :: %{optional(String.t()) => any()}
  ) :: serialized()
  def sign!(payload, jwk, sig_alg, additional_headers \\ %{})

  def sign!(payload, %{"kid" => kid} = jwk, sig_alg, additional_headers),
    do: do_sign!(payload, jwk, sig_alg, Map.put(additional_headers, "kid", kid))
  def sign!(payload, jwk, sig_alg, additional_headers),
    do: do_sign!(payload, jwk, sig_alg, additional_headers)

  defp do_sign!(<<_::binary>> = payload, jwk, sig_alg, additional_headers) do
    jwk
    |> JOSE.JWK.from_map()
    |> JOSE.JWS.sign(payload, Map.merge(additional_headers, %{"alg" => sig_alg}))
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp do_sign!(payload, jwk, sig_alg, additional_headers) do
    payload
    |> Jason.encode!()
    |> sign!(jwk, sig_alg, additional_headers)
  end

  @doc """
  Verifies the signature of a JWS, and returns its content and the signature key

  The function also filters the key using `JOSEUtils.JWKS.verification_keys/2` with the
  whitelisted signature algorithms. If the JWS has an identifier (`"kid"`), it only uses
  that specific key.

  ## Example
      iex> JOSE.crypto_fallback(true)
      iex> jwk_ed25519 = JOSE.JWK.generate_key({:okp, :Ed25519})
      iex> jwk_ed25519_map = jwk_ed25519 |> JOSE.JWK.to_map() |> elem(1)
      iex> signed_ed25519 = JOSE.JWS.sign(jwk_ed25519, "{}", %{ "alg" => "EdDSA" }) |> JOSE.JWS.compact |> elem(1)
      iex> JOSEUtils.JWS.verify(signed_ed25519, jwk_ed25519_map, ["RS256"])
      :error
      iex> JOSEUtils.JWS.verify(signed_ed25519, jwk_ed25519_map, ["EdDSA"]) |> elem(0)
      :ok
  """
  @spec verify(
          jws :: serialized(),
          jwk_or_jwks :: JOSEUtils.JWK.t() | [JOSEUtils.JWK.t()],
          allowed_algs :: [JOSEUtils.JWA.sig_alg()]
        ) :: {:ok, {verified_content :: binary(), JOSEUtils.JWK.t()}} | :error
  def verify(jws, %{} = jwk, allowed_algs) do
    verify(jws, [jwk], allowed_algs)
  end

  def verify(jws, jwks, allowed_algs) do
    with {:ok, header} <- peek_header(jws),
         true <- header["alg"] in allowed_algs do
      jwks =
        case header do
          %{"alg" => _, "kid" => jws_kid} ->
            Enum.filter(jwks, fn jwk -> jwk["kid"] == jws_kid end)

          _ ->
            jwks
        end
        |> JOSEUtils.JWKS.verification_keys(header["alg"])

      do_verify(jws, header, jwks)
    else
      _ ->
        :error
    end
  end

  @spec do_verify(
          jws :: serialized(),
          map(),
          jwk_or_jwks :: JOSEUtils.JWK.t() | [JOSEUtils.JWK.t()]
        ) :: {:ok, {binary(), JOSEUtils.JWK.t()}} | :error
  defp do_verify(jws, header, %{} = jwk) do
    case JOSE.JWS.verify_strict(JOSE.JWK.from_map(jwk), [header["alg"]], jws) do
      {true, verified_content, _} ->
        {:ok, {verified_content, jwk}}

      _ ->
        :error
    end
  end

  defp do_verify(jws, header, jwks) when is_list(jwks) do
    Enum.find_value(
      jwks,
      :error,
      fn jwk ->
        case do_verify(jws, header, jwk) do
          {:ok, _} = result ->
            result

          :error ->
            false
        end
      end
    )
  end
end
