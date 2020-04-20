defmodule JOSEUtils.JWA do
  @moduledoc """
  Helper functions to work with JOSE algorithms
  """

  @typedoc """
  Signature algorithm

  One of:
  - "Ed25519"
  - "Ed448"
  - "EdDSA"
  - "ES256"
  - "ES384"
  - "ES512"
  - "HS256"
  - "HS384"
  - "HS512"
  - "Poly1305"
  - "PS256"
  - "PS384"
  - "PS512"
  - "RS256"
  - "RS384"
  - "RS512"
  - "none"
  """
  @type sig_alg :: String.t()

  @typedoc """
  Algorithm (`"alg"`) used for encryption

  One of:
  - "A128GCMKW"
  - "A128KW"
  - "A192GCMKW"
  - "A192KW"
  - "A256GCMKW"
  - "A256KW"
  - "C20PKW"
  - "ECDH-1PU"
  - "ECDH-1PU+A128GCMKW"
  - "ECDH-1PU+A128KW"
  - "ECDH-1PU+A192GCMKW"
  - "ECDH-1PU+A192KW"
  - "ECDH-1PU+A256GCMKW"
  - "ECDH-1PU+A256KW"
  - "ECDH-1PU+C20PKW"
  - "ECDH-ES"
  - "ECDH-ES+A128GCMKW"
  - "ECDH-ES+A128KW"
  - "ECDH-ES+A192GCMKW"
  - "ECDH-ES+A192KW"
  - "ECDH-ES+A256GCMKW"
  - "ECDH-ES+A256KW"
  - "ECDH-ES+C20PKW"
  - "PBES2-HS256+A128GCMKW"
  - "PBES2-HS256+A128KW"
  - "PBES2-HS384+A192GCMKW"
  - "PBES2-HS384+A192KW"
  - "PBES2-HS512+A256GCMKW"
  - "PBES2-HS512+A256KW"
  - "PBES2-HS512+C20PKW"
  - "RSA-OAEP"
  - "RSA-OAEP-256"
  - "RSA1_5"
  - "dir"
  """
  @type enc_alg :: String.t()

  @typedoc """
  Encryption (`"enc"`) algorithm used for encryption

  One of:
  - "A128CBC-HS256"
  - "A128GCM"
  - "A192CBC-HS384"
  - "A192GCM"
  - "A256CBC-HS512",
  - "A256GCM"
  - "C20P"
  - "XC20P"
  """
  @type enc_enc :: String.t()

  @doc """
  Returns the JOSE algorithm from aan X509 signature algorithm, or `nil` if it has no JOSE
  equivalent
  """
  @spec x509_to_jose_sig_alg(x509_alg :: tuple()) :: sig_alg() | nil
  def x509_to_jose_sig_alg({1, 2, 840, 113_549, 1, 1, 11}), do: "RS256"
  def x509_to_jose_sig_alg({1, 2, 840, 113_549, 1, 1, 12}), do: "RS384"
  def x509_to_jose_sig_alg({1, 2, 840, 113_549, 1, 1, 13}), do: "RS512"
  def x509_to_jose_sig_alg({1, 2, 840, 10045, 4, 3, 2}), do: "ES256"
  def x509_to_jose_sig_alg({1, 2, 840, 10045, 4, 3, 3}), do: "ES384"
  def x509_to_jose_sig_alg({1, 2, 840, 10045, 4, 3, 4}), do: "ES512"
  def x509_to_jose_sig_alg({1, 2, 840, 113_549, 1, 1, 5}), do: "RSA1_5"
  def x509_to_jose_sig_alg(_), do: nil
end
