class Rma < Formula
  desc "Ultra-fast Rust-native code intelligence and security analyzer"
  homepage "https://github.com/bumahkib7/rust-monorepo-analyzer"
  version "0.14.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/bumahkib7/rust-monorepo-analyzer/releases/download/v0.14.0/rma-aarch64-apple-darwin.tar.gz"
      sha256 "8fcfb89d15e5dfc9f23b18be837fa2e00d9b4bd520d404ef810b57ed8645acb2"
    end
    on_intel do
      url "https://github.com/bumahkib7/rust-monorepo-analyzer/releases/download/v0.14.0/rma-x86_64-apple-darwin.tar.gz"
      sha256 "c57c97c9c06e95c0193cff42233c513f18cb75eeb2d74174e6f114359b52f180"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/bumahkib7/rust-monorepo-analyzer/releases/download/v0.14.0/rma-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "b9c01b98f968368891bb8cae5bd44a94b6027ef2cc0571dd1dec3295901d13b1"
    end
    on_intel do
      url "https://github.com/bumahkib7/rust-monorepo-analyzer/releases/download/v0.14.0/rma-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "7d116c6489a6d7eaa8bcfa62071da2b79e178b738338815d5d6a45d69d384558"
    end
  end

  def install
    bin.install "rma"
    generate_completions_from_executable(bin/"rma", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/rma --version")

    # Test scanning a simple Rust file
    (testpath/"test.rs").write('fn main() { println!("hello"); }')
    output = shell_output("#{bin}/rma scan #{testpath} --format json 2>&1")
    assert_match "findings", output
  end
end
