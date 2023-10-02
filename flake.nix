{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, ... }@inputs:
    let
      inherit (pkgs) writeShellScript;
      inherit (pkgs.lib.lists) foldl' flatten unique map filter elem genList;
      inherit (pkgs.lib.strings) splitString concatStringsSep stringLength optionalString;
      inherit (pkgs.lib.attrsets) attrValues mapAttrsToList filterAttrs attrNames mapAttrs foldlAttrs;

      pkgs = inputs.nixpkgs.legacyPackages."x86_64-linux";

      getopts = opts: (
        let
          cases = mapAttrsToList
            (n: v:
              let
                attrIsLong = stringLength n > 1;
                short = "-${v.short or (optionalString (! attrIsLong) n)}";
                long = "--${v.long or (optionalString attrIsLong n)}";
                match = filter (x: !(elem x [ "-" "--" ])) [ short long ];
                takes = v.takes or 1;
                inherit (v) run;
                shifts = concatStringsSep "\n" (genList (_: "shift") takes);
              in
              ''
                ${concatStringsSep "|" match})
                  ${run}
                  ${shifts}
                ;;
              '')
            opts;
        in
        ''
          positionalOpts=()
          while [[ "$#" -gt 0 ]]; do
            currentOpt="$1"
            shift
            case $currentOpt in
              ${concatStringsSep "\n" cases}

              *)
                positionalOpts+=("$currentOpt")
              ;;
            esac
          done
        ''
      );
    in {
      secrix = fInputs: {
        type = "app";
        program = let
          help = concatStringsSep "\n" (map (x: "echo \"${x}\"") (splitString "\n" ''
            ENCRYPTION
              nix run .#secrix create OUTPUT-FILE -- [-u USER | --all-users] [-s SYSTEM | --all-systems] [-r RECIPIENT]
                -u | --user
                  Add all keys (for all secrets and systems) for a given user as specified
                  in any defaultEncryptKeys or encryptKeys option. Can be specified multiple
                  times.
                -s | --system
                  Add the hostPubKey for the system specified. Can be specified multiple
                  times.
                -r | --recipient
                  Add an ad hoc public key for encryption. Can be specified multiple times.

            REENCRYPTION
              nix run .#secrix rekey FILE -- -i IDENTITY-FILE [-u USER | --all-users] [-s SYSTEM | --all-systems] [-r RECIPIENT]
                -i | --identity
                  Required. The path of a private key which can be used to decrypt the file.
                -u, -s, and -r operate the same as in ENCRYPTION.

            EDITING
              nix run .#secrix edit FILE -- -i IDENTITY_FILE [-u USER | --all-users] [-s SYSTEM | --all-systems] [-r RECIPIENT]
                All flags operate the same as in REENCRYPTION.

            OTHER
              nix run .#secrix -- [-h | --help]
                Display this message.
              nix run .#secrix -- (--list-users | --list-systems | -l)
                --list-users
                  List all users found.
                --list-systems
                  List all systems found.
                -l | --list-all
                  List all users and systems found.

            NOTES
              * Due to the way nix run works, all flags must be specified after the --.
                Positional parameters can be placed wherever, however must be in the same
                order as specified in the documentation.
              * Due to constraints in nix, existing keys used for encryption will not be
                re-used and must be specified again. Hoefully this will be fixed in the
                future.
          ''));

          opts = {
            u = {
              long = "user";
              run = ''
                if [[ -z "''${userKeys["$1"]}" ]]; then
                  echo "No user found: $1" 1>&2
                  exit 1
                fi
                recips+="''${userKeys["$1"]}"
              '';
            };
            all-users = {
              run = ''
                recips+="''${userKeys[@]}"
              '';
              takes = 0;
            };
            s = {
              long = "system";
              run = ''
                if [[ -z "''${hostKeys["$1"]}" ]]; then
                  echo "No system found: $1" 1>&2
                  exit 1
                fi
                recips+="''${hostKeys["$1"]}"
              '';
            };
            i = {
              long = "identity";
              run = ''
                identityFile="$1"
              '';
            };
            all-systems = {
              run = ''
                recips+="''${hostKeys["$1"]}"
              '';
              takes = 0;
            };
            list-users.run = ''
              for i in "''${!userKeys[@]}"; do
                echo "$i"
              done
              exit 0
            '';
            list-systems.run = ''
              for i in "''${!hostKeys[@]}"; do
                echo "$i"
              done
              exit 0
            '';
            l = {
              long = "list-all";
              run = ''
                echo "USERS:"
                for i in "''${!userKeys[@]}"; do
                  echo "  $i"
                done
                echo ""
                echo "SYSTEMS:"
                for i in "''${!hostKeys[@]}"; do
                  echo "  $i"
                done
                exit 0
              '';
            };
            r = {
              long = "recipient";
              run = ''
                recips+="-r '$1'"
              '';
            };
            h = {
              long = "help";
              run = ''
                help
                exit 0
              '';
            };
          };

          edit = "\${VISUAL:-\${EDITOR:-${pkgs.neovim}/bin/nvim}}";
          allServices = flatten (mapAttrsToList (_: v: attrValues v.config.secrix.services) fInputs.nixosConfigurations);
          allSystemSecrets = flatten (mapAttrsToList (_: v: attrValues v.config.secrix.system.secrets) fInputs.nixosConfigurations);
          allSecrets = allSystemSecrets ++ flatten (map (x: attrValues x.secrets) allServices);
          allUsers = flatten (map (x: x.encryptKeys) allSecrets);
          allKeys = foldl' (a: x: a // mapAttrs (n: v: unique (v ++ (a.${n} or []))) x) {} allUsers;
          hostKeys = mapAttrs (_: v: " -r '${v.config.secrix.hostPubKey}'") (filterAttrs (_: v': v'.config.secrix.hostPubKey != null) fInputs.nixosConfigurations);
        in (writeShellScript "secrix" ''
          function help {
            ${help}
          }
          recips=""
          identityFile=""
          declare -A userKeys
          declare -A hostKeys
          ${foldlAttrs (a: n: v: ''
            ${a}
            userKeys['${n}']="${foldl' (a': x: "${a'} -r '${x}'") "" v}"
          '') "" allKeys}
          ${foldlAttrs (a: n: v: ''
            ${a}
            hostKeys['${n}']="${v}"
          '') "" hostKeys}
          ${getopts opts}

          if [[ ''${#positionalOpts[@]} == 0 ]]; then
            help
            exit 1
          fi
          case "''${positionalOpts[0]}" in
            create)
              tmpsec="$(${pkgs.coreutils}/bin/mktemp)"
              ${edit} "$tmpsec"
              if [[ $? != 0 ]]; then
                echo "Editor exited with a non-zero status. Doing nothing."
              else
                eval ${pkgs.rage}/bin/rage -e $recips "$tmpsec" > "''${positionalOpts[1]}"
              fi
              ${pkgs.coreutils}/bin/rm "$tmpsec"
            ;;
            rekey)
              if [[ -z "''$identityFile" ]]; then
                echo "No given identity file."
                exit 1
              elif ! [[ -e "''$identityFile" ]]; then
                echo "Identity file does not exist."
                exit 1
              fi
              tmpsec="$(${pkgs.coreutils}/bin/mktemp)"
              if ! eval ${pkgs.rage}/bin/rage -d -i "$identityFile" "''${positionalOpts[1]}" > "$tmpsec"; then
                ${pkgs.coreutils}/bin/rm "$tmpsec"
                exit 1
              fi
              eval ${pkgs.rage}/bin/rage -e $recips "$tmpsec" > "''${positionalOpts[1]}"
              ${pkgs.coreutils}/bin/rm "$tmpsec"
            ;;
            edit)
              if [[ -z "''$identityFile" ]]; then
                echo "No given identity file."
                exit 1
              elif ! [[ -e "''$identityFile" ]]; then
                echo "Identity file does not exist."
                exit 1
              fi
              tmpsec="$(${pkgs.coreutils}/bin/mktemp)"
              if ! eval ${pkgs.rage}/bin/rage -d -i "$identityFile" "''${positionalOpts[1]}" > "$tmpsec"; then
                ${pkgs.coreutils}/bin/rm "$tmpsec"
                exit 1
              fi
              ${edit} "$tmpsec"
              if [[ $? != 0 ]]; then
                echo "Editor exited with a non-zero status. Doing nothing."
              else
                eval ${pkgs.rage}/bin/rage -e $recips "$tmpsec" > "''${positionalOpts[1]}"
              fi
              ${pkgs.coreutils}/bin/rm "$tmpsec"
            ;;
            *)
            ;;
          esac
        '').outPath;
      };
      nixosModules = {
        secrix = import ./module.nix;
        default = import ./module.nix;
      };
    };
}
