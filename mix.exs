defmodule JOSEUtils.MixProject do
  use Mix.Project

  def project do
    [
      app: :jose_utils,
      version: "0.1.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps()
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
end
