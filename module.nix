{ pkgs, config, ... }:
let
  inherit (builtins) isFunction readFile;
  inherit (pkgs) writeText copyPathToStore writeShellScript;
  inherit (pkgs.lib.lists) foldl';
  inherit (pkgs.lib.strings) concatStringsSep optionalString;
  inherit (pkgs.lib.trivial) id;
  inherit (pkgs.lib.modules) mkForce;
  inherit (pkgs.lib.attrsets) mapAttrsToList attrValues concatMapAttrs attrNames;

  foldlAttrs = pkgs.lib.attrsets.foldlAttrs or (f: i: s: foldl' (a: n: f a n s.${n}) i (attrNames s));

  d = x: builtins.trace x x;

  sysConfig = config;
  cfg = config.secrix;
in
{
  options = with pkgs.lib; {
    secrix = {
      ageBin = mkOption {
        type = types.str;
        default = "${pkgs.age}/bin/age";
        defaultText = literalExpression ''
          "''${pkgs.age}/bin/age"
        '';
        description = ''
          The age bin to use for encryption and decryption.
        '';
      };
      system = {
        secretsDir = {
          name = mkOption {
            type = types.str;
            default = "system-keys";
            description = ''
              The name of the directory for system secrets. It will end up as `/run/<name>`.
            '';
          };
          permissions = mkOption {
            type = types.str;
            default = "111";
            description = ''
              Permissions for the directory containing system secrets.
            '';
          };
          user = mkOption {
            type = types.str;
            default = "0";
            description = ''
              The user that owns the directory for system secrets.
            '';
          };
          group = mkOption {
            type = types.str;
            default = "0";
            description = ''
              The group that owns the directory for system secrets.
            '';
          };
        };
        secretsServiceName = mkOption {
          type = types.str;
          default = "system-keys";
          description = ''
            The name of the service that manages system secrets.
          '';
        };
        secrets = mkOption {
          type = types.attrsOf (types.submodule ({ name, config, ... }: {
            options = {
              name = mkOption {
                type = types.str;
                default = name;
                description = ''
                  The name of the secret. This defaults to the attribute name. This is simply a
                  referential token to the secret, however if no name is set for the decrypted file,
                  this will be used.
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
                  Local location of the secret.
                '';
              };
              decrypted = {
                name = mkOption {
                  type = types.str;
                  default = config.name;
                  defaultText = literalExpression ''
                    config.secrix.system.secrets.<name>.name
                  '';
                  description = ''
                    The name of the decrypted file on disk. This defaults to the secret name.
                  '';
                };
                mode = mkOption {
                  type = types.str;
                  default = "0400";
                  description = ''
                    Permissions of the secret when decrypted.
                  '';
                };
                user = mkOption {
                  type = types.str;
                  default = "0";
                  description = ''
                    Secret user.
                  '';
                };
                group = mkOption {
                  type = types.str;
                  default = "0";
                  description = ''
                    Secret group.
                  '';
                };
                path = mkOption {
                  type = types.str;
                  default = "/run/${cfg.system.secretsDir.name}/${config.name}";
                  defaultText = literalExpression ''
                    "/run/''${config.secrix.system.secretsDir.name}/''${config.secrix.system.secrets.<name>.name}"
                  '';
                  readOnly = true;
                  description = ''
                    The path to the secret when decrypted on disk. This is automatically set by
                    secrix and is available only for reference.
                  '';
                };
                builder = mkOption {
                  type = types.nullOr (types.either types.lines (types.functionTo types.lines));
                  default = null;
                  description = ''
                    A builder script (if needed) to perform additional actions on the secret before
                    it ends up in its final location.

                    If this is a function that yields a string, it will be passed a single argument
                    which is the final location of the built file.

                    If this is a string, a special bash variable $inFile can be used to reference
                    the secret as it is, however there will be no reference available to its final
                    destination as that will be up to the builder. Use a string only if you know
                    what you're doing.
                  '';
                };
              };
            };
          }));
          default = {};
          description = ''
            An attribute set of secrets that will be decrypted on the system. System secrets will
            be decrypted at system start and will exist decrypted for the uptime of the system but
            will not remain on disk if the system is shut down sanely.
          '';
        };
      };
      hostIdentityFile = mkOption {
        type = types.str;
        default = "/etc/ssh/ssh_host_ed25519_key";
        description = ''
          The private key of the host that will be decrypting the secret.
        '';
      };
      defaultEncryptKeys = mkOption {
        type = types.attrsOf (types.listOf types.str);
        default = {};
        description = ''
          The default encryption keys for all secrets. This will be overriden for any given secret
          if `encryptKeys` is specified for that secret.
        '';
      };
      hostPubKey = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          The public key for the host that the secrets will exist on.
        '';
      };
      services = mkOption {
        type = types.attrsOf (types.submodule (outer@{ name, config, ... }: {
          options = {
            secretsDirName = mkOption {
              type = types.str;
              default = "${name}-keys";
              description = ''
                The directory name for the service secrets.
              '';
            };
            systemdService = mkOption {
              type = types.str;
              default = name;
              description = ''
                The name fo the systemd service that the secrets contained within will be bound
                to. This defaults to the attribute name.
              '';
            };
            additionalRuntimeDirNames = mkOption {
              type = types.listOf types.str;
              default = [ ];
              description = ''
                In the case that the systemd service these secrets will be bound to has a
                RuntimeDirectory specified as a string, secrix will be unable to add an additional
                RuntimeDirectory, so add that here.
              '';
            };
            forceRuntimeDirs = mkOption {
              type = types.bool;
              default = false;
              description = ''
                Set this to true of the service these secrets will be bound to has a
                RuntimeDirectory already specified as a string.
              '';
            };
            secretsServiceName = mkOption {
              type = types.str;
              default = "${name}-keys";
              description = ''
                The name of the service that will decrypt the keys.
              '';
            };
            secrets = mkOption {
              type = types.attrsOf (types.submodule ({ name, config, ... }: {
                options = {
                  name = mkOption {
                    type = types.str;
                    default = name;
                    description = ''
                      The name of the secret. This defaults to the attribute name. This is simply
                      a referential token to the secret, however if no name is set for the
                      decrypted file, this will be used.
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
                      Local location of the secret.
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
                        The name of the decrypted file on disk. This defaults to the secret name.
                      '';
                    };
                    mode = mkOption {
                      type = types.str;
                      default = "0400";
                      description = ''
                        Permissions of the secret when decrypted.
                      '';
                    };
                    user = mkOption {
                      type = types.nullOr types.str;
                      default = let
                        servUser = hasAttrByPath [ "serviceConfig" "User" ] sysConfig.systemd.services.${outer.config.systemdService};
                        servDynUser = attrByPath [ "serviceConfig" "DynamicUser" ] false sysConfig.systemd.services.${outer.config.systemdService};
                        user = attrByPath [ "serviceConfig" "User" ] "0" sysConfig.systemd.services.${outer.config.systemdService};
                        userSearch = if user == "0" then "root" else user;
                        sysUser = length (filter (x: x.name == userSearch) (attrValues (sysConfig.users.users or {}))) > 0;
                      in if (servUser && sysUser) then
                        user
                      else if servDynUser then
                        null
                      else "0";
                      defaultText = literalExpression ''
                        with config.systemd.services.<name>.serviceConfig; User or (if DynamicUser then null else "root")
                      '';
                      # in "0";
                      description = ''
                        Secret user.
                      '';
                    };
                    group = mkOption {
                      type = types.str;
                      default = sysConfig.users.users.${config.decrypted.user}.group or "0";
                      defaultText = literalExpression ''
                        config.users.users.''${config.secrix.services.<name>.decrypted.group}.group
                      '';
                      description = ''
                        Secret group.
                      '';
                    };
                    path = mkOption {
                      type = types.str;
                      default = "/run/${outer.config.secretsDirName}/${config.name}";
                      defaultText = literalExpression ''
                        let cfg = config.secrix.services.<name>; in
                        "/run/''${cfg.secretsDirName}/''${cfg.name}"
                      '';
                      readOnly = true;
                      description = ''
                        The path to the secret when decrypted on disk. This is automatically set
                        by secrix and is available only for reference.
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
                        available to its final destination as that will be up to the builder. Use
                        a string only if you know what you're doing.
                      '';
                    };
                  };
                };
              }));
              description = ''
                An attribute set of secrets that will be decrypted on the system. Service secrets
                will be decrypted at the start of and will exist for the lifetime of the service
                they are bound to.
              '';
            };
          };
        }));
        default = { };
        description = ''
          An attribute set of systemd service names to which to bind secrets. All secrets bound to
          a service will exist only for the lifetime of the service.
        '';
      };
    };
  };

  config =
    let
      c = s: "${pkgs.coreutils}/bin/${s}";
      runKeyDir = "/run/${cfg.system.secretsDir.name}";
      allSecrets = (foldlAttrs (a: _: v: a // foldlAttrs (a': _: v': a' // { ${v'.decrypted.name} = copyPathToStore v'.encrypted.file; }) { } v.secrets) { } cfg.services) //
        foldlAttrs (a: _: v: a // { ${v.decrypted.name} = copyPathToStore v.encrypted.file; }) { } cfg.system.secrets;
        systemKeysServices = concatMapAttrs (n: v: let
          runKeyPath = "${runKeyDir}/${v.decrypted.name}";
        in { "secrix-system-secret-${n}" = {
        wantedBy = [ "secrix-system-secrets.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStop = writeShellScript "secrix-rm-${n}" ''
            ${c "rm"} -f ${runKeyPath}
          '';
        };
        script = let
          decrypt = p: ''
            ${cfg.ageBin} -d -i "${cfg.hostIdentityFile}" "${allSecrets.${v.decrypted.name}}" > "${p}"
          '';
          mkBuilder = s: ''
            inFile="$(${c "mktemp"})"
            ${decrypt "$inFile"}
            ${s}
            ${c "rm"} $inFile
          '';
          chPerms = ''
            ${c "chown"} ${v.decrypted.user}:${v.decrypted.group} "${runKeyPath}"
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
      }; }) cfg.system.secrets;
      systemKeysMainService = {
        secrix-system-secrets = {
          script = ''
            ${c "mkdir"} -p ${runKeyDir}
          '';
          wantedBy = [ "multi-user.target" ];
          unitConfig.PropagatesStopTo = map (x: "secrix-system-secret-${x}.service") (attrNames cfg.system.secrets);
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            RuntimeDirectory = cfg.system.secretsDir.name;
            RuntimeDirectoryMode = cfg.system.secretsDir.permissions;
            User = cfg.system.secretsDir.user;
            Group = cfg.system.secretsDir.group;
          };
        };
      };
    in
    {
      # x - systemd service
      systemd.services = systemKeysServices // systemKeysMainService // foldl'
        (a: x: a // {
          ${x.secretsServiceName} = {
            before = [ "${x.systemdService}.service" ];
            bindsTo = [ "${x.systemdService}.service" ];
            serviceConfig = {
              Type = "oneshot";
              RemainAfterExit = true;
            };
            script =
              let
                runKeyDir = "/run/${x.secretsDirName}";
                # v - secret
                cpKeys = mapAttrsToList
                  (_: v:
                    let
                      runKeyPath = "${runKeyDir}/${v.decrypted.name}";
                      decrypt = p: ''
                        ${cfg.ageBin} -d -i "${cfg.hostIdentityFile}" "${allSecrets.${v.decrypted.name}}" > "${p}"
                      '';
                      mkBuilder = s: ''
                        inFile="$(${c "mktemp"})"
                        ${decrypt "$inFile"}
                        ${s}
                        ${c "rm"} $inFile
                      '';
                      chPerms = optionalString (v.decrypted.user != null) ''
                        ${c "chown"} ${v.decrypted.user}:${v.decrypted.group} "${runKeyPath}"
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
            serviceConfig.RuntimeDirectory = (if x.forceRuntimeDirs then mkForce else id) ([ x.secretsServiceName ] ++ x.additionalRuntimeDirNames);
          };
        })
        { }
        (attrValues cfg.services);
    };
}
