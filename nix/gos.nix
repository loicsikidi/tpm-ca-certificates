{
  pkgs,
  lib,
}:
pkgs.buildGoModule rec {
  pname = "gos";
  version = "unstable-2025-01-26";

  src = pkgs.fetchFromGitHub {
    owner = "imjasonh";
    repo = "gos";
    rev = "7a6478a0b6bf4b48135133ddb1930d6dbbd88c09";
    hash = "sha256-DxNdXZfUG6sg9Du5xgQDVGau7TtBNsDZAgJ5fs+NJpI=";
  };

  vendorHash = null;

  ldflags = [
    "-s"
    "-w"
  ];

  meta = with lib; {
    description = "Go Script Runner - run Go files as scripts with inline dependencies";
    homepage = "https://github.com/imjasonh/gos";
    license = licenses.asl20;
    maintainers = [];
  };
}
