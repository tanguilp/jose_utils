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
end
