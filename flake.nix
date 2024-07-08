{
  description = "pwndbg";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  # LLDB is broken under the version of nixpkgs all the other packages use, but
  # we can't use a version that's so new it's expecting Python 3.12.
  inputs.nixpkgs-llvm.url = "github:NixOS/nixpkgs/23cf1985454db1e127c9418feee2d04a56ebe3ba";

  inputs.poetry2nix = {
    url = "github:nix-community/poetry2nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-llvm,
      poetry2nix,
    }:
    let
      # Self contained packages for: Debian, RHEL-like (yum, rpm), Alpine, Arch packages
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
      forPortables = nixpkgs.lib.genAttrs [
        "deb"
        "rpm"
        "apk"
        "archlinux"
      ];

      pkgsBySystem = forAllSystems (
        system:
        import nixpkgs {
          inherit system;
          overlays = [ poetry2nix.overlays.default ];
        }
      );
      llvmPkgsBySystem = forAllSystems(
        system:
        import nixpkgs-llvm {
          inherit system;
        }
      );
      pkgUtil = forAllSystems (system: import ./nix/bundle/pkg.nix { pkgs = pkgsBySystem.${system}; });

      portableDrv =
        system:
        import ./nix/portable.nix {
          pkgs = pkgsBySystem.${system};
          pwndbg = self.packages.${system}.pwndbg;
        };
      portableDrvs =
        system:
        forPortables (
          packager:
          pkgUtil.${system}.buildPackagePFPM {
            inherit packager;
            drv = portableDrv system;
            config = ./nix/bundle/nfpm.yaml;
            preremove = ./nix/bundle/preremove.sh;
          }
        );
      tarballDrv = system: {
        tarball = pkgUtil.${system}.buildPackageTarball { drv = portableDrv system; };
      };
    in
    {
      packages = forAllSystems (
        system:
        {
          pwndbg = import ./nix/pwndbg.nix {
            pkgs = pkgsBySystem.${system};
            python3 = pkgsBySystem.${system}.python3;
            gdb = pkgsBySystem.${system}.gdb;
            inputs.pwndbg = self;
          };
          default = self.packages.${system}.pwndbg;
          pwndbg-dev = import ./nix/pwndbg.nix {
            pkgs = pkgsBySystem.${system};
            python3 = pkgsBySystem.${system}.python3;
            gdb = pkgsBySystem.${system}.gdb;
            inputs.pwndbg = self;
            isDev = true;
          };
          pwndbg-lldb = import ./nix/pwndbg.nix {
            pkgs = pkgsBySystem.${system};
            python3 = pkgsBySystem.${system}.python3;
            gdb = pkgsBySystem.${system}.gdb;
            inputs.pwndbg = self;
            isDev = true;
            isLLDB = true;
            llvmPkgs = llvmPkgsBySystem.${system};
          };
        }
        // (portableDrvs system)
        // (tarballDrv system)
      );

      devShells = forAllSystems (
        system:
        import ./nix/devshell.nix {
          pkgs = pkgsBySystem.${system};
          python3 = pkgsBySystem.${system}.python3;
          inputs.pwndbg = self;
          isLLDB = true;
          llvmPkgs = llvmPkgsBySystem.${system};
        }
      );
    };
}
