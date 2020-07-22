defmodule JOSEUtils.MixProject do
  use Mix.Project

  def project do
    [
      app: :jose_utils,
      description: "Convenience functions to work with JOSE (JSON Object Signing and Encryption)",
      version: "0.3.2",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: [
        main: "readme",
        extras: ["README.md"]
      ],
      package: package(),
      source_url: "https://github.com/tanguilp/jose_utils"
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:jason, "~> 1.1"},
      {:jose, "~> 1.10.1"},
      {:x509, "~> 0.8.0"}
    ]
  end

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/jose_utils"}
    ]
  end
end
