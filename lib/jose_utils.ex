defmodule JOSEUtils do
  @moduledoc """
  FIXME
  """

  @doc """
  Returns `true` if the string is an encrypted JWT, `false` otherwise

  ## Example

      iex> jwe_token = "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJzODNFNjhPNjhsWlM5ZVprIiwidGFnIjoieF9Ea2M5dm1LMk5RQV8tU2hvTkFRdyJ9.8B2qX8fVEa-s61RsZXqkCg.J7yJ8sKLbUlzyor6.FRs.BhBwImTv9B14NwVuxmfU6A"
      "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJzODNFNjhPNjhsWlM5ZVprIiwidGFnIjoieF9Ea2M5dm1LMk5RQV8tU2hvTkFRdyJ9.8B2qX8fVEa-s61RsZXqkCg.J7yJ8sKLbUlzyor6.FRs.BhBwImTv9B14NwVuxmfU6A"
      iex> JOSEUtils.is_jwe?(jwe_token)
      true

      iex> jws_token = "eyJhbGciOiJFZDI1NTE5In0.e30.xyg2LTblm75KbLFJtROZRhEgAFJdlqH9bhx8a9LO1yvLxNLhO9fLqnFuU3ojOdbObr8bsubPkPqUfZlPkGHXCQ"
      "eyJhbGciOiJFZDI1NTE5In0.e30.xyg2LTblm75KbLFJtROZRhEgAFJdlqH9bhx8a9LO1yvLxNLhO9fLqnFuU3ojOdbObr8bsubPkPqUfZlPkGHXCQ"
      iex> JOSEUtils.is_jwe?(jws_token)
      false
  """

  @spec is_jwe?(String.t()) :: boolean()
  def is_jwe?(input) when is_binary(input) do
    JOSE.JWE.expand(input)

    true
  rescue
    _ ->
      false
  end

  @doc """
  Returns `true` if the string is an signed JWT, `false` otherwise

      iex(2)> JOSEUtils.is_jws?("eyJhbGciOiJIUzI1NiJ9.e30.5paAJxaOXSqRUIXrP_vJXUZu2SCBH-ojgP4D6Xr6GPU")
      true
      iex(3)> JOSEUtils.is_jws?("Some.string")
      false
  """

  @spec is_jws?(String.t()) :: boolean()
  def is_jws?(input) do
    JOSE.JWS.expand(input)

    true
  rescue
    _ ->
      false
  end
end
