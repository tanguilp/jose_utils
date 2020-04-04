defmodule JOSEUtils.JWS do
  @moduledoc """
  Util function to work with signed JWTs
  """

  @typedoc """
  Serialized JWS signed token, for instance:

      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
  """
  @type serialized :: String.t()

  @doc """
  Verifies the signature of a JWS, and returns its content and the signature key

  The function also filters the key using `JOSEUtils.JWKS.verification_keys/2` with the
  whitelisted signature algorithms. If the JWS has an identifier (`"kid"`), it only uses
  that specific key.

  ## Example
      iex> JOSE.crypto_fallback(true)
      iex> jwk_ed25519   = JOSE.JWK.generate_key({:okp, :Ed25519})
      iex> jwk_ed25519_map = jwk_ed25519 |> JOSE.JWK.to_map() |> elem(1)
      iex> signed_ed25519 = JOSE.JWS.sign(jwk_ed25519, "{}", %{ "alg" => "Ed25519" }) |> JOSE.JWS.compact |> elem(1)
      iex> JOSEUtils.JWS.verify(signed_ed25519, jwk_ed25519_map, ["RS256"])
      :error
      iex> JOSEUtils.JWS.verify(signed_ed25519, jwk_ed25519_map, ["Ed25519"]) |> elem(0)
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
    case String.split(jws, ".") do
      [header_b64, _, _] ->
        with {:ok, header_str} <- Base.decode64(header_b64, padding: false),
             {:ok, header} <- Jason.decode(header_str),
             true <- header["alg"] in allowed_algs
        do
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
