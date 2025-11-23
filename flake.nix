{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, ... }@inputs:
    let
      inherit (builtins) toString;
      inherit (pkgs) writeShellScript;
      inherit (pkgs.lib.lists) foldl' flatten unique map filter elem genList last length range toList;
      inherit (pkgs.lib.strings) splitString concatStringsSep stringLength optionalString concatMapStrings;
      inherit (pkgs.lib.trivial) warnIf;
      inherit (pkgs.lib.attrsets) attrValues mapAttrsToList filterAttrs attrNames mapAttrs foldlAttrs recursiveUpdate;

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

            STDIN & STDOUT
              nix run .#secrix encrypt OUTPUT-FILE -- [-u USER | --all-users] [-s SYSTEM | --all-systems] [-r RECIPIENT]
                Reads secret from stdin and stores encrypted secret into file.
                -u, -s, and -r operate the same as in ENCRYPTION.
              nix run .#secrix decrypt FILE -- -i IDENTITY_FILE
                Decrypts secret from file and outputs it on stdout.
                -i operates the same as in REENCRYPTION.

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
                recips+="''${hostKeys[@]}"
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
                recips+=" -r '$@'"
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
          applicableConfs = filterAttrs (_: v: v ? config.secrix) fInputs.nixosConfigurations;
          allServices = flatten (mapAttrsToList (_: v: attrValues v.config.secrix.services) applicableConfs);
          allSystemSecrets = flatten (mapAttrsToList (_: v: attrValues v.config.secrix.system.secrets) applicableConfs);
          allSecrets = allSystemSecrets ++ flatten (map (x: attrValues x.secrets) allServices);
          allUsers = flatten (map (x: x.encryptKeys) allSecrets);
          allKeys = foldl' (a: x: a // mapAttrs (n: v: unique (v ++ (a.${n} or []))) x) {} (allUsers ++ (foldl' (a: x: a ++ [ x.config.secrix.defaultEncryptKeys ]) [] (attrValues applicableConfs)));
          hostKeys = mapAttrs (_: v: " -r '${v.config.secrix.hostPubKey}'") (filterAttrs (_: v': v'.config.secrix.hostPubKey != null) applicableConfs);
          ageBin = let
            currentSystem = pkgs.system;
            matching = attrValues (
              filterAttrs (_: c: c.pkgs.system == currentSystem) applicableConfs
            );
            bins = unique (map (c: c.config.secrix.ageBin) matching);
          in
            if bins == []
            then "${pkgs.age}/bin/age"
            else builtins.elemAt bins (length bins - 1);
        in (writeShellScript "secrix" ''
          function help {
            ${help}
          }
          function checkid {
            if [[ -z "$identityFile" ]]; then
              echo "No given identity file." >&2
              exit 1
            elif ! [[ -e "$identityFile" ]]; then
              echo "Identity file does not exist." >&2
              exit 1
            fi
          }
          status=0
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
            encrypt)
              tmpfin="$(${pkgs.coreutils}/bin/mktemp)"
              if ! eval ${ageBin} -e $recips - > "$tmpfin"; then
                echo "Encrypt failed with non-zero status. Abandoning." >&2
                status=1
              else
                ${pkgs.coreutils}/bin/mv "$tmpfin" "''${positionalOpts[1]}"
              fi
            ;;
            decrypt)
              if ! eval ${ageBin} -d -i "$identityFile" "''${positionalOpts[1]}"; then
                echo "Decrypt failed with non-zero status. Abandoning." >&2
                status=1
              fi
            ;;
            create)
              tmpsec="$(${pkgs.coreutils}/bin/mktemp)"
              if ! ${edit} "$tmpsec"; then
                echo "Editor exited with non-zero status. Abandoning." >&2
                status=1
              else
                tmpfin="$(${pkgs.coreutils}/bin/mktemp)"
                if ! eval ${ageBin} -e $recips "$tmpsec" > "$tmpfin"; then
                  echo "Encrypt failed with non-zero status. Abandoning." >&2
                  status=1
                else
                  ${pkgs.coreutils}/bin/mv "$tmpfin" "''${positionalOpts[1]}"
                fi
              fi
            ;;
            rekey)
              checkid
              tmpsec="$(${pkgs.coreutils}/bin/mktemp)"
              if ! eval ${ageBin} -d -i "$identityFile" "''${positionalOpts[1]}" > "$tmpsec"; then
                echo "Decrypt failed with non-zero status. Abandoning." >&2
                status=1
              else
                tmpfin="$(${pkgs.coreutils}/bin/mktemp)"
                if ! eval ${ageBin} -e $recips "$tmpsec" > "$tmpfin"; then
                  echo "Reencrypt failed with non-zero status. Abandoning." >&2
                  status=1
                else
                  ${pkgs.coreutils}/bin/mv "$tmpfin" "''${positionalOpts[1]}"
                fi
              fi
            ;;
            edit)
              checkid
              tmpsec="$(${pkgs.coreutils}/bin/mktemp)"
              if ! eval ${ageBin} -d -i "$identityFile" "''${positionalOpts[1]}" > "$tmpsec"; then
                echo "Decrypt failed with non-zero status. Abandoning." >&2
                status=1
              else
                if ! ${edit} "$tmpsec"; then
                  echo "Editor exited with non-zero status. Abandoning." >&2
                  status=1
                else
                  tmpfin="$(${pkgs.coreutils}/bin/mktemp)"
                  if ! eval ${ageBin} -e $recips "$tmpsec" > "$tmpfin"; then
                    echo "Encrypt failed with non-zero status. Abandoning." >&2
                    status=1
                  else
                    ${pkgs.coreutils}/bin/mv "$tmpfin" "''${positionalOpts[1]}"
                  fi
                fi
              fi
            ;;
            *)
              echo "Unknown action '""''${positionalOpts[0]}.'" >&2
            ;;
          esac
          ${pkgs.coreutils}/bin/rm -f "$tmpfin"
          ${pkgs.coreutils}/bin/rm -f "$tmpsec"
          exit $status
        '').outPath;
      };
      nixosModules = {
        secrix = import ./module.nix;
        default = import ./module.nix;
      };
      checks.x86_64-linux = {
        e2e-test = pkgs.testers.nixosTest {
          name = "secrix-e2e-test";
          extraPythonPackages = p: [ p.termcolor ];
          nodes = {
            machine = { config, ... }: {
              imports = [
                self.nixosModules.secrix
              ];
              services.openssh.enable = true;
              system.activationScripts.replaceHostKey = ''
                mkdir -p /etc/ssh
                cp ${./keys/test-host-key} /etc/ssh/ssh_host_ed25519_key
                chmod 400 !!$
                cp ${./keys/test-host-key.pub} /etc/ssh/ssh_host_ed25519_key.pub
                chmod 644 !!$
              '';
              secrix = {
                hostPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKn43IR9yp8zhEWUhRmiA+rnd05t99ubTMJY7/ljd+yj chloe@freyja";
                defaultEncryptKeys.user = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM64lwxKaEiwWLsV5Y/g0/4ZGPN+Ri2gz15mHVd716pu chloe@freyja" ];
                system.secrets.secret1.encrypted.file = ./secrets/system-secret1;
                services = {
                  test1.secrets.service-secret1.encrypted.file = ./secrets/service-secret1;
                  test3.secrets.service-secret3.encrypted.file = ./secrets/service-secret3;
                  test4.secrets.service-secret4.encrypted.file = ./secrets/service-secret4;
                  test5.secrets.service-secret5.encrypted.file = ./secrets/service-secret5;
                  test6.secrets.service-secret6 = {
                    encrypted.file = ./secrets/service-secret6;
                    decrypted.mode = "0271";
                  };
                  test7.secrets.service-secret7.encrypted.file = ./secrets/service-secret1;
                  test8.secrets.service-secret1.encrypted.file = ./secrets/service-secret1;
                };
              };
              systemd.services = {
                test1 = {
                  script = ''
                    set -x
                    cat ${config.secrix.services.test1.secrets.service-secret1.decrypted.path}
                  '';
                  serviceConfig = {
                    Type = "oneshot";
                    User = "test1";
                    RemainAfterExit = true;
                  };
                };
                test2 = {
                  script = ''
                    set -x
                    cat ${config.secrix.services.test1.secrets.service-secret1.decrypted.path}
                  '';
                  serviceConfig = {
                    Type = "oneshot";
                    User = "test2";
                    RemainAfterExit = true;
                  };
                };
                test3 = {
                  script = ''
                    set -x
                    cat ${config.secrix.services.test1.secrets.service-secret1.decrypted.path}
                  '';
                  serviceConfig = {
                    User = "test1";
                    Type = "oneshot";
                  };
                };
                test4 = {
                  script = ''
                    set -x
                    cat /run/test4-keys/missing-secret
                  '';
                  serviceConfig = {
                    User = "test4";
                    Type = "oneshot";
                  };
                };
                test5 = {
                  script = ''
                    set -x
                    cat ${config.secrix.services.test5.secrets.service-secret5.decrypted.path}
                  '';
                };
                test6 = {
                  script = ''
                    set -x
                    [[ $(stat -c '%a' ${config.secrix.services.test6.secrets.service-secret6.decrypted.path}) == $((10#${config.secrix.services.test6.secrets.service-secret6.decrypted.mode})) ]]
                  '';
                  serviceConfig.Type = "oneshot";
                };
                test7 = {
                  script = ''
                    set -x
                    cat ${config.secrix.services.test7.secrets.service-secret7.decrypted.path}
                  '';
                  serviceConfig.Type = "oneshot";
                };
                test8 = {
                  script = ''
                    set -x
                    cat ${config.secrix.services.test8.secrets.service-secret1.decrypted.path}
                  '';
                  serviceConfig.Type = "oneshot";
                };
                any.script = ''
                  set -x
                  cat ${config.secrix.system.secrets.secret1.decrypted.path}
                '';
              };
              users = foldl' (a: x: recursiveUpdate a {
                users.${x} = {
                  isSystemUser = true;
                  group = x;
                };
                groups.${x} = {};
              }) {} [ "test1" "test2" "test4" ];
            };
          };
          testScript = let
            SKIP = r: xs: mapAttrs (_: _: ''
              from termcolor import colored; print(colored("!!!!!!!!!!SKIPPED: ${r}!!!!!!!!!!", "red", attrs=["bold"]))
            '') xs;
            printTest = x: ''
              print("==========${x}==========")
            '';
            cleanup = concatMapStrings (x: ''
              machine.systemctl("stop test${toString x}.service")
            '') (range 1 3);
          in ''
            start_all()
            machine.wait_for_unit("multi-user.target")
            machine.wait_for_unit("system-keys.service")
          '' + concatMapStrings (x: ''
            ${foldlAttrs (a: n: v: ''
              ${a}
              ${printTest n}
              ${v}
              ${cleanup}
            '') "" x}
          '') [
            {
              "The system secret exists." = ''
                machine.succeed("cat /run/system-keys/secret1")
              '';
            }
            {
              "If you define a system secret, it is available in any service." = ''
                machine.succeed("systemctl start any.service")
                machine.succeed("cat /run/system-keys/secret1")
              '';
            }
            {
              "If you define a service secret, it is available in its service." = ''
                machine.succeed("systemctl start test1.service")
                machine.systemctl("stop test1.service")
              '';
            }
            {
              "If you define a service secret, it is not available in another service." = ''
                machine.succeed("systemctl start test1.service")
                machine.fail("systemctl start test2.service")
              '';
            }
            {
              "If you define a service secret, it is not available if the service is not running." = ''
                machine.succeed("systemctl start test1.service")
                ${cleanup}
                machine.fail("systemctl start test3.service")
              '';
            }
            {
              "If a service fails to start, its keys should not exist." = ''
                machine.fail("systemctl start test4.service")
                machine.fail("cat /run/test4-keys/service-secret4")
              '';
            }
            {
              "A service secret should have the appropriate permissions set." = ''
                machine.succeed("systemctl start test6.service")
              '';
            }
            {
              "A secret should be able to be reused without issue." = ''
                machine.succeed("systemctl start test7.service")
              '';
            }
            {
              "Secrets under 2 different services should be able to have the same name." = ''
                machine.succeed("systemctl start test8.service")
              '';
            }
          ];
        };
      };
    };
}
