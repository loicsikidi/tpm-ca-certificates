{
  pkgs ? import <nixpkgs> {},
  isUnstable ? false,
}:
pkgs.callPackage ./nix/package.nix {
  src =
    if isUnstable
    then pkgs.lib.cleanSource ./.
    else null;
}
