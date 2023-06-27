{ pkgs ? import <nixpkgs> { } }:
with pkgs;
mkShell {
  buildInputs = [
    nixpkgs-fmt
    pkgs.go
    pkgs.gopls
  ];

  shellHook = ''
    # ...
  '';
}
