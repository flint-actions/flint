{ pkgs ? import <nixpkgs> { } }:
with pkgs;
mkShell {
  buildInputs = [
    nixpkgs-fmt
    pkgs.go
    pkgs.gopls
    pkgs.goreleaser
    pkgs.shellcheck
  ];

  shellHook = ''
    # ...
  '';
}
