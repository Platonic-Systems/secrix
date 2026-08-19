{ config, lib, pkgs, ... }:
let
  inherit (builtins) readFile;
  inherit (pkgs) writeText copyPathToStore writeShellScript;
  inherit (lib) isFunction mkOption mkIf types literalExpression;
  inherit (lib.lists) foldl';
  inherit (lib.strings) concatStringsSep optionalString;
  inherit (lib.trivial) id;
  inherit (lib.modules) mkForce;
  inherit (lib.attrsets) mapAttrsToList attrValues concatMapAttrs attrNames;

  foldlAttrs = lib.attrsets.foldlAttrs or (f: i: s: foldl' (a: n: f a n s.${n}) i (attrNames s));

  cfg = config.secrix;

  # User-specific runtime directory (Linux: $XDG_RUNTIME_DIR, macOS: DARWIN_USER_TEMP_DIR)
  userRuntimeDir = let
    inherit (pkgs.stdenv.hostPlatform) isDarwin;
  in
    if isDarwin
    then "$(${lib.getExe pkgs.getconf} DARWIN_USER_TEMP_DIR)/secrix"
    else "\${XDG_RUNTIME_DIR}/secrix";
in
{
  options = with lib; {
    secrix = {
      ageBin = mkOption {
        type = types.str;
        default = "${pkgs.age}/bin/age";
        defaultText = literalExpression ''
          "''${pkgs.age}/bin/age"
        '';
        description = ''
          The age binary to use for encryption and decryption.
        '';
      };

      identityPaths = mkOption {
        type = types.listOf types.path;
        default = [
          "${config.home.homeDirectory}/.ssh/id_ed25519"
          "${config.home.homeDirectory}/.ssh/id_rsa"
        ];
        defaultText = literalExpression ''
          [
            "''${config.home.homeDirectory}/.ssh/id_ed25519"
            "''${config.home.homeDirectory}/.ssh/id_rsa"
          ]
        '';
        description = ''
          Path to SSH keys to be used as identities in age decryption.
          These should be password-less keys for automated decryption.
        '';
      };

      secretsDir = {
        name = mkOption {
          type = types.str;
          default = "secrix";
          description = ''
            The name of the directory for secrets within the user runtime directory.
            On Linux, secrets will be stored in $XDG_RUNTIME_DIR/<name>.
          '';
        };
        permissions = mkOption {
          type = types.str;
          default = "0700";
          description = ''
            Permissions for the directory containing secrets.
          '';
        };
      };

      defaultEncryptKeys = mkOption {
        type = types.attrsOf (types.listOf types.str);
        default = {};
        description = ''
          The default encryption keys for all secrets. This will be overridden
          for any given secret if `encryptKeys` is specified for that secret.
        '';
      };

      hostPubKey = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          The public key for the host (optional). Used by the secrix CLI tool
          to encrypt secrets for specific hosts.
        '';
      };

      secrets = mkOption {
        type = types.attrsOf (types.submodule ({ name, config, ... }: {
          options = {
            name = mkOption {
              type = types.str;
              default = name;
              description = ''
                The name of the secret. This defaults to the attribute name.
              '';
            };
            encryptKeys = mkOption {
              type = types.attrsOf (types.listOf types.str);
              default = cfg.defaultEncryptKeys;
              defaultText = literalExpression ''
                config.secrix.defaultEncryptKeys
              '';
              description = ''
                Public keys with which to encrypt the secret.
              '';
            };
            encrypted.file = mkOption {
              type = types.path;
              description = ''
                Local location of the encrypted secret.
              '';
            };
            decrypted = {
              name = mkOption {
                type = types.str;
                default = config.name;
                defaultText = literalExpression ''
                  config.secrix.secrets.<name>.name
                '';
                description = ''
                  The name of the decrypted file on disk.
                '';
              };
              mode = mkOption {
                type = types.str;
                default = "0400";
                description = ''
                  Permissions of the secret when decrypted.
                '';
              };
              path = mkOption {
                type = types.str;
                default = "${userRuntimeDir}/${cfg.secretsDir.name}/${config.name}";
                defaultText = literalExpression ''
                  "$XDG_RUNTIME_DIR/secrix/''${config.secrix.secrets.<name>.name}"
                '';
                readOnly = true;
                description = ''
                  The path to the secret when decrypted on disk. This is automatically
                  set by secrix and is available only for reference.
                '';
              };
              builder = mkOption {
                type = types.nullOr (types.either types.lines (types.functionTo types.lines));
                default = null;
                description = ''
                  A builder script (if needed) to perform additional actions on the secret
                  before it ends up in its final location.

                  If this is a function that yields a string, it will be passed a single
                  argument which is the final location of the built file.

                  If this is a string, a special bash variable $inFile can be used to
                  reference the secret as it is, however there will be no reference
                  available to its final destination as that will be up to the builder.
                  Use a string only if you know what you're doing.
                '';
              };
            };
          };
        }));
        default = {};
        description = ''
          An attribute set of secrets that will be decrypted for the user session.
          Secrets will be available for the lifetime of the user session and will
          not persist across reboots.
        '';
      };

      services = mkOption {
        type = types.attrsOf (types.submodule (outer@{ name, config, ... }: {
          options = {
            secretsDirName = mkOption {
              type = types.str;
              default = "${name}-keys";
              description = ''
                The directory name for the service secrets within the user runtime directory.
              '';
            };
            systemdService = mkOption {
              type = types.str;
              default = name;
              description = ''
                The name of the systemd user service that the secrets will be bound to.
                This defaults to the attribute name.
              '';
            };
            secrets = mkOption {
              type = types.attrsOf (types.submodule ({ name, config, ... }: {
                options = {
                  name = mkOption {
                    type = types.str;
                    default = name;
                    description = ''
                      The name of the secret. This defaults to the attribute name.
                    '';
                  };
                  encryptKeys = mkOption {
                    type = types.attrsOf (types.listOf types.str);
                    default = cfg.defaultEncryptKeys;
                    defaultText = literalExpression ''
                      config.secrix.defaultEncryptKeys
                    '';
                    description = ''
                      Public keys with which to encrypt the secret.
                    '';
                  };
                  encrypted.file = mkOption {
                    type = types.path;
                    description = ''
                      Local location of the encrypted secret.
                    '';
                  };
                  decrypted = {
                    name = mkOption {
                      type = types.str;
                      default = config.name;
                      defaultText = literalExpression ''
                        config.secrix.services.<name>.secrets.<name>.name
                      '';
                      description = ''
                        The name of the decrypted file on disk.
                      '';
                    };
                    mode = mkOption {
                      type = types.str;
                      default = "0400";
                      description = ''
                        Permissions of the secret when decrypted.
                      '';
                    };
                    path = mkOption {
                      type = types.str;
                      default = "${userRuntimeDir}/${outer.config.secretsDirName}/${config.name}";
                      defaultText = literalExpression ''
                        "$XDG_RUNTIME_DIR/''${config.secrix.services.<name>.secretsDirName}/''${config.secrix.services.<name>.secrets.<name>.name}"
                      '';
                      readOnly = true;
                      description = ''
                        The path to the secret when decrypted on disk. This is automatically
                        set by secrix and is available only for reference.
                      '';
                    };
                    builder = mkOption {
                      type = types.nullOr (types.either types.lines (types.functionTo types.lines));
                      default = null;
                      description = ''
                        A builder script (if needed) to perform additional actions on the
                        secret before it ends up in its final location.

                        If this is a function that yields a string, it will be passed a
                        single argument which is the final location of the built file.

                        If this is a string, a special bash variable $inFile can be used
                        to reference the secret as it is, however there will be no reference
                        available to its final destination as that will be up to the builder.
                        Use a string only if you know what you're doing.
                      '';
                    };
                  };
                };
              }));
              description = ''
                An attribute set of secrets that will be decrypted for the user service.
                Service secrets will be decrypted at the start of and will exist for the
                lifetime of the service they are bound to.
              '';
            };
          };
        }));
        default = {};
        description = ''
          An attribute set of systemd user service names to which to bind secrets.
          All secrets bound to a service will exist only for the lifetime of the service.
        '';
      };
    };
  };

  config = let
    c = s: "${pkgs.coreutils}/bin/${s}";
    runKeyDir = "${userRuntimeDir}/${cfg.secretsDir.name}";

    # All secrets (service + session-level)
    allSecrets =
      (foldlAttrs (a: _: v: a // foldlAttrs (a': _: v': a' // { ${v'.decrypted.name} = copyPathToStore v'.encrypted.file; }) { } v.secrets) { } cfg.services) //
      foldlAttrs (a: _: v: a // { ${v.decrypted.name} = copyPathToStore v.encrypted.file; }) { } cfg.secrets;

    # Find the first available identity file
    identityFile = let
      existing = builtins.filter (p: builtins.pathExists p) cfg.identityPaths;
    in
      if existing != [] then builtins.head existing
      else throw "secrix: No identity file found. Set secrix.identityPaths to point to your SSH keys.";

    # Session-level (user) secrets services
    userKeysServices = concatMapAttrs (n: v: let
      runKeyPath = "${runKeyDir}/${v.decrypted.name}";
    in { "secrix-user-secret-${n}" = {
      wantedBy = [ "secrix-user-secrets.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStop = writeShellScript "secrix-rm-${n}" ''
          ${c "rm"} -f ${runKeyPath}
        '';
      };
      script = let
        decrypt = p: ''
          ${cfg.ageBin} -d -i "${identityFile}" "${allSecrets.${v.decrypted.name}}" > "${p}"
        '';
        mkBuilder = s: ''
          inFile="$(${c "mktemp"})"
          ${decrypt "$inFile"}
          ${s}
          ${c "rm"} $inFile
        '';
        chPerms = ''
          ${c "chmod"} ${v.decrypted.mode} "${runKeyPath}"
        '';
        scr = if v.decrypted.builder == null then
          "${decrypt runKeyPath}"
        else if isFunction v.decrypted.builder then
          mkBuilder "${v.decrypted.builder runKeyPath}"
        else
          mkBuilder "${v.decrypted.builder}";
      in ''
        ${c "mkdir"} -p ${runKeyDir}
        ${scr}
        ${chPerms}
      '';
    }; }) cfg.secrets;

    userKeysMainService = {
      secrix-user-secrets = {
        script = ''
          ${c "mkdir"} -p ${runKeyDir}
        '';
        wantedBy = [ "default.target" ];
        unitConfig.PropagatesStopTo = map (x: "secrix-user-secret-${x}.service") (attrNames cfg.secrets);
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
      };
    };

    # Service-bound secrets
    serviceKeysServices = foldl'
      (a: x: a // {
        ${x.secretsServiceName} = {
          before = [ "${x.systemdService}.service" ];
          bindsTo = [ "${x.systemdService}.service" ];
          unitConfig.PartOf = [ "${x.systemdService}.service" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          script =
            let
              runKeyDir = "${userRuntimeDir}/${x.secretsDirName}";
              cpKeys = mapAttrsToList
                (_: v:
                  let
                    runKeyPath = "${runKeyDir}/${v.decrypted.name}";
                    decrypt = p: ''
                      ${cfg.ageBin} -d -i "${identityFile}" "${allSecrets.${v.decrypted.name}}" > "${p}"
                    '';
                    mkBuilder = s: ''
                      inFile="$(${c "mktemp"})"
                      ${decrypt "$inFile"}
                      ${s}
                      ${c "rm"} $inFile
                    '';
                    chPerms = ''
                      ${c "chmod"} ${v.decrypted.mode} "${runKeyPath}"
                    '';
                    scr =
                      if v.decrypted.builder == null then
                        "${decrypt runKeyPath}"
                      else if isFunction v.decrypted.builder then
                        mkBuilder "${v.decrypted.builder runKeyPath}"
                      else
                        mkBuilder "${v.decrypted.builder}";
                  in
                  ''
                    ${c "mkdir"} -p "${runKeyDir}"
                    ${scr}
                    ${chPerms}
                  '')
                x.secrets;
            in
            ''
              ${concatStringsSep "\n" cpKeys}
            '';
        };
        ${x.systemdService} = {
          after = [ "${x.secretsServiceName}.service" ];
          bindsTo = [ "${x.secretsServiceName}.service" ];
          serviceConfig.Environment = [
            "SECRIX_SECRETS_DIR=${userRuntimeDir}/${x.secretsDirName}"
          ];
        };
      })
      { }
      (attrValues cfg.services);
  in mkIf (cfg.secrets != {} || cfg.services != {}) {
    systemd.user.services = userKeysServices // userKeysMainService // serviceKeysServices;
  };
}
